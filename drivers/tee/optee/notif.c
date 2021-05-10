// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2021, Linaro Limited
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/arm-smccc.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tee_drv.h>
#include "optee_private.h"
#include "optee_smc.h"
#include "optee_rpc_cmd.h"

struct notif_entry {
	struct list_head link;
	struct completion c;
	u_int key;
};

static u32 get_async_notif_value(optee_invoke_fn *invoke_fn, bool *value_valid,
				 bool *value_pending)
{
	struct arm_smccc_res res;

	invoke_fn(OPTEE_SMC_GET_ASYNC_NOTIF_VALUE, 0, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0)
		return 0;
	*value_valid = (res.a2 & OPTEE_SMC_ASYNC_NOTIF_VALUE_VALID);
	*value_pending = (res.a2 & OPTEE_SMC_ASYNC_NOTIF_VALUE_PENDING);
	return res.a1;
}

static irqreturn_t notif_irq_handler(int irq, void *dev_id)
{
	struct optee *optee = dev_id;
	bool do_bottom_half = false;
	bool value_valid;
	bool value_pending;
	u32 value;

	do {
		value = get_async_notif_value(optee->invoke_fn, &value_valid,
					      &value_pending);
		if (!value_valid)
			break;

		if (value == OPTEE_SMC_ASYNC_NOTIF_VALUE_DO_BOTTOM_HALF)
			do_bottom_half = true;
		else
			optee_notif_send(optee, value);
	} while (value_pending);

	if (do_bottom_half)
		return IRQ_WAKE_THREAD;
	return IRQ_HANDLED;
}

static irqreturn_t notif_irq_thread_fn(int irq, void *dev_id)
{
	struct optee *optee = dev_id;

	optee_do_bottom_half(optee->notif.ctx);

	return IRQ_HANDLED;
}

static bool have_key(struct optee *optee, u_int key)
{
	struct notif_entry *entry;

	list_for_each_entry(entry, &optee->notif.db, link)
		if (entry->key == key)
			return true;

	return false;
}

int optee_notif_wait(struct optee *optee, u_int key)
{
	unsigned long flags;
	struct notif_entry *entry;
	int rc = 0;

	if (key > optee->notif.max_key)
		return -EINVAL;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	init_completion(&entry->c);
	entry->key = key;

	spin_lock_irqsave(&optee->notif.lock, flags);

	/*
	 * If the bit is already set it means that the key has already
	 * been posted and we must not wait.
	 */
	if (test_bit(key, optee->notif.bitmap)) {
		clear_bit(key, optee->notif.bitmap);
		goto out;
	}

	/*
	 * Check if someone is already waiting for this key. If there is
	 * it's a programming error.
	 */
	if (have_key(optee, key)) {
		rc = -EBUSY;
		goto out;
	}

	list_add_tail(&entry->link, &optee->notif.db);

	/*
	 * Unlock temporarily and wait for completion.
	 */
	spin_unlock_irqrestore(&optee->notif.lock, flags);
	wait_for_completion(&entry->c);
	spin_lock_irqsave(&optee->notif.lock, flags);

	list_del(&entry->link);
out:
	spin_unlock_irqrestore(&optee->notif.lock, flags);

	kfree(entry);

	return rc;
}

int optee_notif_send(struct optee *optee, u_int key)
{
	unsigned long flags;
	struct notif_entry *entry;

	if (key > optee->notif.max_key)
		return -EINVAL;

	spin_lock_irqsave(&optee->notif.lock, flags);

	list_for_each_entry(entry, &optee->notif.db, link)
		if (entry->key == key) {
			complete(&entry->c);
			goto out;
		}

	/* Only set the bit in case there where nobody waiting */
	set_bit(key, optee->notif.bitmap);
out:
	spin_unlock_irqrestore(&optee->notif.lock, flags);

	return 0;
}

int optee_notif_init(struct optee *optee, u_int max_key, u_int irq)
{
	struct tee_context *ctx;
	int rc;

	ctx = tee_dev_open_helper(optee->teedev);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	optee->notif.ctx = ctx;

	spin_lock_init(&optee->notif.lock);
	INIT_LIST_HEAD(&optee->notif.db);
	optee->notif.bitmap = bitmap_zalloc(max_key, GFP_KERNEL);
	if (!optee->notif.bitmap) {
		rc = -ENOMEM;
		goto err_put_ctx;
	}
	optee->notif.max_key = max_key;

	rc = request_threaded_irq(irq, notif_irq_handler, notif_irq_thread_fn,
				  0, "optee_notification", optee);
	if (rc)
		goto err_free_bitmap;

	optee->notif.irq = irq;

	return 0;

err_free_bitmap:
	kfree(optee->notif.bitmap);
err_put_ctx:
	tee_dev_ctx_put(optee->notif.ctx);

	return rc;
}

void optee_notif_uninit(struct optee *optee)
{
	if (optee->notif.ctx) {
		optee_stop_async_notif(optee->notif.ctx);
		if (optee->notif.irq) {
			free_irq(optee->notif.irq, optee);
			irq_dispose_mapping(optee->notif.irq);
		}

		/*
		 * The thread normally working with optee->notif.ctx was
		 * stopped with free_irq() above.
		 *
		 * Note we're not using teedev_close_context() or
		 * tee_client_close_context() since we have already called
		 * tee_device_put() while initializing to avoid a circular
		 * reference counting.
		 */
		tee_dev_ctx_put(optee->notif.ctx);
	}

	kfree(optee->notif.bitmap);
}
