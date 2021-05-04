// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include "optee_bench.h"
#include "optee_private.h"
#include "optee_smc.h"

struct wq_entry {
	struct list_head link;
	struct completion c;
	u32 key;
};

void optee_wait_queue_init(struct optee_wait_queue *priv)
{
	mutex_init(&priv->mu);
	INIT_LIST_HEAD(&priv->db);
}

void optee_wait_queue_exit(struct optee_wait_queue *priv)
{
	mutex_destroy(&priv->mu);
}

static void handle_rpc_func_cmd_get_time(struct optee_msg_arg *arg)
{
	struct timespec64 ts;

	if (arg->num_params != 1)
		goto bad;
	if ((arg->params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT)
		goto bad;

	ktime_get_real_ts64(&ts);
	arg->params[0].u.value.a = ts.tv_sec;
	arg->params[0].u.value.b = ts.tv_nsec;

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static struct wq_entry *wq_entry_get(struct optee_wait_queue *wq, u32 key)
{
	struct wq_entry *w;

	mutex_lock(&wq->mu);

	list_for_each_entry(w, &wq->db, link)
		if (w->key == key)
			goto out;

	w = kmalloc(sizeof(*w), GFP_KERNEL);
	if (w) {
		init_completion(&w->c);
		w->key = key;
		list_add_tail(&w->link, &wq->db);
	}
out:
	mutex_unlock(&wq->mu);
	return w;
}

static void wq_sleep(struct optee_wait_queue *wq, u32 key)
{
	struct wq_entry *w = wq_entry_get(wq, key);

	if (w) {
		wait_for_completion(&w->c);
		mutex_lock(&wq->mu);
		list_del(&w->link);
		mutex_unlock(&wq->mu);
		kfree(w);
	}
}

static void wq_wakeup(struct optee_wait_queue *wq, u32 key)
{
	struct wq_entry *w = wq_entry_get(wq, key);

	if (w)
		complete(&w->c);
}

static void handle_rpc_func_cmd_wq(struct optee *optee,
				   struct optee_msg_arg *arg)
{
	if (arg->num_params != 1)
		goto bad;

	if ((arg->params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	switch (arg->params[0].u.value.a) {
	case OPTEE_MSG_RPC_WAIT_QUEUE_SLEEP:
		wq_sleep(&optee->wait_queue, arg->params[0].u.value.b);
		break;
	case OPTEE_MSG_RPC_WAIT_QUEUE_WAKEUP:
		wq_wakeup(&optee->wait_queue, arg->params[0].u.value.b);
		break;
	default:
		goto bad;
	}

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_wait(struct optee_msg_arg *arg)
{
	u32 msec_to_wait;

	if (arg->num_params != 1)
		goto bad;

	if ((arg->params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	msec_to_wait = arg->params[0].u.value.a;

	/* Go to interruptible sleep */
	msleep_interruptible(msec_to_wait);

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_supp_cmd(struct tee_context *ctx,
				struct optee_msg_arg *arg)
{
	struct tee_param *params;

	arg->ret_origin = TEEC_ORIGIN_COMMS;

	params = kmalloc_array(arg->num_params, sizeof(struct tee_param),
			       GFP_KERNEL);
	if (!params) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	if (optee_from_msg_param(params, arg->num_params, arg->params)) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	arg->ret = optee_supp_thrd_req(ctx, arg->cmd, arg->num_params, params);

	if (optee_to_msg_param(arg->params, arg->num_params, params))
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
out:
	kfree(params);
}

static struct tee_shm *cmd_alloc_suppl(struct tee_context *ctx, size_t sz)
{
	u32 ret;
	struct tee_param param;
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct tee_shm *shm;

	param.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
	param.u.value.a = OPTEE_MSG_RPC_SHM_TYPE_APPL;
	param.u.value.b = sz;
	param.u.value.c = 0;

	ret = optee_supp_thrd_req(ctx, OPTEE_MSG_RPC_CMD_SHM_ALLOC, 1, &param);
	if (ret)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&optee->supp.mutex);
	/* Increases count as secure world doesn't have a reference */
	shm = tee_shm_get_from_id(optee->supp.ctx, param.u.value.c);
	mutex_unlock(&optee->supp.mutex);
	return shm;
}

int optee_rpc_process_shm_alloc(struct tee_shm *shm,
				struct optee_msg_param *msg_param, void **list)
{
	phys_addr_t pa;
	size_t sz;
	size_t offs;
	struct page **pages;
	size_t page_num;
	void *pages_list;

	if (tee_shm_get_pa(shm, 0, &pa))
		return -EINVAL;

	sz = tee_shm_get_size(shm);

	if (tee_shm_is_registered(shm)) {
		pages = tee_shm_get_pages(shm, &page_num);
		if (!pages || !page_num)
			return -EINVAL;

		offs = tee_shm_get_page_offset(shm);
		if (offs >= OPTEE_MSG_NONCONTIG_PAGE_SIZE)
			return -EINVAL;

		pages_list = optee_allocate_pages_list(page_num);
		if (!pages_list)
			return -ENOMEM;

		/*
		 * In the least bits of u.tmem.buf_ptr we store buffer offset
		 * from 4k page, as described in OP-TEE ABI.
		 */

		msg_param->attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT |
				  OPTEE_MSG_ATTR_NONCONTIG;
		msg_param->u.tmem.buf_ptr = virt_to_phys(pages_list) | offs;
		msg_param->u.tmem.size = sz;
		msg_param->u.tmem.shm_ref = (unsigned long)shm;
		optee_fill_pages_list(pages_list, pages, page_num,
				      tee_shm_get_page_offset(shm));
		*list = pages_list;
	} else {
		msg_param->attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
		msg_param->u.tmem.buf_ptr = pa;
		msg_param->u.tmem.size = sz;
		msg_param->u.tmem.shm_ref = (unsigned long)shm;
		*list = NULL;
	}

	return 0;
}

static void handle_rpc_func_cmd_shm_alloc(struct tee_context *ctx,
					  struct optee_msg_arg *arg,
					  struct optee_call_ctx *call_ctx)
{
	struct tee_shm *shm;
	void *pages_list;
	size_t sz;
	size_t n;
	int rc;

	arg->ret_origin = TEEC_ORIGIN_COMMS;

	if (!arg->num_params ||
	    arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	for (n = 1; n < arg->num_params; n++) {
		if (arg->params[n].attr != OPTEE_MSG_ATTR_TYPE_NONE) {
			arg->ret = TEEC_ERROR_BAD_PARAMETERS;
			return;
		}
	}

	sz = arg->params[0].u.value.b;
	switch (arg->params[0].u.value.a) {
	case OPTEE_MSG_RPC_SHM_TYPE_APPL:
		shm = cmd_alloc_suppl(ctx, sz);
		break;
	case OPTEE_MSG_RPC_SHM_TYPE_KERNEL:
		shm = tee_shm_alloc(ctx, sz, TEE_SHM_MAPPED);
		break;
	case OPTEE_MSG_RPC_SHM_TYPE_GLOBAL:
		shm = tee_shm_alloc(ctx, sz, TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);
		break;
	default:
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	if (IS_ERR(shm)) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	rc = optee_rpc_process_shm_alloc(shm, arg->params, &pages_list);
	if (rc == -ENOMEM) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		goto bad;
	} else if (rc) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		goto bad;
	}

	if (tee_shm_is_registered(shm)) {
		call_ctx->pages_list = pages_list;
		call_ctx->num_entries = shm->num_pages;
	}

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	tee_shm_free(shm);
}

static void cmd_free_suppl(struct tee_context *ctx, struct tee_shm *shm)
{
	struct tee_param param;

	param.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
	param.u.value.a = OPTEE_MSG_RPC_SHM_TYPE_APPL;
	param.u.value.b = tee_shm_get_id(shm);
	param.u.value.c = 0;

	/*
	 * Match the tee_shm_get_from_id() in cmd_alloc_suppl() as secure
	 * world has released its reference.
	 *
	 * It's better to do this before sending the request to supplicant
	 * as we'd like to let the process doing the initial allocation to
	 * do release the last reference too in order to avoid stacking
	 * many pending fput() on the client process. This could otherwise
	 * happen if secure world does many allocate and free in a single
	 * invoke.
	 */
	tee_shm_put(shm);

	optee_supp_thrd_req(ctx, OPTEE_MSG_RPC_CMD_SHM_FREE, 1, &param);
}

static void handle_rpc_func_cmd_shm_free(struct tee_context *ctx,
					 struct optee_msg_arg *arg)
{
	struct tee_shm *shm;

	arg->ret_origin = TEEC_ORIGIN_COMMS;

	if (arg->num_params != 1 ||
	    arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	shm = (struct tee_shm *)(unsigned long)arg->params[0].u.value.b;
	switch (arg->params[0].u.value.a) {
	case OPTEE_MSG_RPC_SHM_TYPE_APPL:
		cmd_free_suppl(ctx, shm);
		break;
	case OPTEE_MSG_RPC_SHM_TYPE_KERNEL:
	case OPTEE_MSG_RPC_SHM_TYPE_GLOBAL:
		tee_shm_free(shm);
		break;
	default:
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
	}
	arg->ret = TEEC_SUCCESS;
}

static void free_pages_list(struct optee_call_ctx *call_ctx)
{
	if (call_ctx->pages_list) {
		optee_free_pages_list(call_ctx->pages_list,
				      call_ctx->num_entries);
		call_ctx->pages_list = NULL;
		call_ctx->num_entries = 0;
	}
}

void optee_rpc_finalize_call(struct optee_call_ctx *call_ctx)
{
	free_pages_list(call_ctx);
}

static void handle_rpc_func_cmd_bm_reg(struct optee_msg_arg *arg)
{
	u64 size;
	u64 type;
	u64 paddr;

	if (arg->num_params != 1)
		goto bad;

	if ((arg->params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	type = arg->params[0].u.value.a;
	switch (type) {
	case OPTEE_MSG_RPC_CMD_BENCH_REG_NEW:
		size = arg->params[0].u.value.c;
		paddr = arg->params[0].u.value.b;
		down_write(&optee_bench_ts_rwsem);
		optee_bench_ts_global =
			memremap(paddr, size, MEMREMAP_WB);
		if (!optee_bench_ts_global) {
			up_write(&optee_bench_ts_rwsem);
			goto bad;
		}
		up_write(&optee_bench_ts_rwsem);
		break;
	case OPTEE_MSG_RPC_CMD_BENCH_REG_DEL:
		down_write(&optee_bench_ts_rwsem);
		if (optee_bench_ts_global)
			memunmap(optee_bench_ts_global);
		optee_bench_ts_global = NULL;
		up_write(&optee_bench_ts_rwsem);
		break;
	default:
		goto bad;
	}

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd(struct tee_context *ctx, struct optee *optee,
				struct tee_shm *shm,
				struct optee_call_ctx *call_ctx)
{
	struct optee_msg_arg *arg;

	arg = tee_shm_get_va(shm, 0);
	if (IS_ERR(arg)) {
		pr_err("%s: tee_shm_get_va %p failed\n", __func__, shm);
		return;
	}

	switch (arg->cmd) {
	case OPTEE_MSG_RPC_CMD_GET_TIME:
		handle_rpc_func_cmd_get_time(arg);
		break;
	case OPTEE_MSG_RPC_CMD_WAIT_QUEUE:
		handle_rpc_func_cmd_wq(optee, arg);
		break;
	case OPTEE_MSG_RPC_CMD_SUSPEND:
		handle_rpc_func_cmd_wait(arg);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		free_pages_list(call_ctx);
		handle_rpc_func_cmd_shm_alloc(ctx, arg, call_ctx);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		handle_rpc_func_cmd_shm_free(ctx, arg);
		break;
	case OPTEE_MSG_RPC_CMD_BENCH_REG:
		handle_rpc_func_cmd_bm_reg(arg);
		break;
	default:
		handle_rpc_supp_cmd(ctx, arg);
	}
}

/**
 * optee_handle_rpc() - handle RPC from secure world
 * @ctx:	context doing the RPC
 * @param:	value of registers for the RPC
 * @call_ctx:	call context. Preserved during one OP-TEE invocation
 *
 * Result of RPC is written back into @param.
 */
void optee_handle_rpc(struct tee_context *ctx, struct optee_rpc_param *param,
		      struct optee_call_ctx *call_ctx)
{
	struct tee_device *teedev = ctx->teedev;
	struct optee *optee = tee_get_drvdata(teedev);
	struct tee_shm *shm;
	phys_addr_t pa;

	switch (OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0)) {
	case OPTEE_SMC_RPC_FUNC_ALLOC:
		shm = tee_shm_alloc(ctx, param->a1, TEE_SHM_MAPPED);
		if (!IS_ERR(shm) && !tee_shm_get_pa(shm, 0, &pa)) {
			reg_pair_from_64(&param->a1, &param->a2, pa);
			reg_pair_from_64(&param->a4, &param->a5,
					 (unsigned long)shm);
		} else {
			param->a1 = 0;
			param->a2 = 0;
			param->a4 = 0;
			param->a5 = 0;
		}
		break;
	case OPTEE_SMC_RPC_FUNC_FREE:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		tee_shm_free(shm);
		break;
	case OPTEE_SMC_RPC_FUNC_FOREIGN_INTR:
		/*
		 * A foreign interrupt was raised while secure world was
		 * executing, since they are handled in Linux a dummy RPC is
		 * performed to let Linux take the interrupt through the normal
		 * vector.
		 */
		break;
	case OPTEE_SMC_RPC_FUNC_CMD:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		handle_rpc_func_cmd(ctx, optee, shm, call_ctx);
		break;
	default:
		pr_warn("Unknown RPC func 0x%x\n",
			(u32)OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0));
		break;
	}

	param->a0 = OPTEE_SMC_CALL_RETURN_FROM_RPC;
}

bool optee_rpc_is_ocall(struct optee_rpc_param *param,
			struct optee_call_ctx *call_ctx)
{
	u32 func;
	u64 shm_type;

	struct tee_shm *shm;
	struct optee_msg_arg *arg;

	func = OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0);
	if (func != OPTEE_SMC_RPC_FUNC_CMD)
		return false;

	shm = reg_pair_to_ptr(param->a1, param->a2);
	arg = tee_shm_get_va(shm, 0);

	switch (arg->cmd) {
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		shm_type = arg->params[0].u.value.a;
		if (shm_type != OPTEE_MSG_RPC_SHM_TYPE_CLIENT_APPL)
			break;
		fallthrough;
	case OPTEE_MSG_RPC_CMD_OCALL:
		call_ctx->rpc_shm = shm;
		call_ctx->rpc_arg = arg;
		call_ctx->thread_id = param->a3;
		return true;
	default:
		break;
	}

	return false;
}
