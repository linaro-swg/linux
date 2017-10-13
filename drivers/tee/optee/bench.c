/*
 * Copyright (c) 2017, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <asm/arch_timer.h>
#include <linux/smp.h>

#include "optee_bench.h"

struct optee_ts_global *optee_bench_ts_global;
struct rw_semaphore optee_bench_ts_rwsem;

void optee_bm_timestamp(void)
{
	struct optee_ts_cpu_buf *cpu_buf;
	struct optee_time_st ts_data;
	uint64_t ts_i;
	void *ret_addr;
	int cur_cpu = 0;
	int ret;

	down_read(&optee_bench_ts_rwsem);

	if (!optee_bench_ts_global) {
		up_read(&optee_bench_ts_rwsem);
		return;
	}

	cur_cpu = get_cpu();

	if (cur_cpu >= optee_bench_ts_global->cores) {
		put_cpu();
		up_read(&optee_bench_ts_rwsem);
		return;
	}

	ret_addr = __builtin_return_address(0);

	cpu_buf = &optee_bench_ts_global->cpu_buf[cur_cpu];
	ts_i = __sync_fetch_and_add(&cpu_buf->head, 1);
	ts_data.cnt = arch_counter_get_cntvct();
	ts_data.addr = (uintptr_t)ret_addr;
	ts_data.src = OPTEE_BENCH_KMOD;
	cpu_buf->stamps[ts_i & OPTEE_BENCH_MAX_MASK] = ts_data;

	up_read(&optee_bench_ts_rwsem);

	put_cpu();
}
