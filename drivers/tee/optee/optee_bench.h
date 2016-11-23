/*
 * Copyright (c) 2016, Linaro Limited
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

#ifndef _OPTEE_BENCH_H
#define _OPTEE_BENCH_H

#include <linux/tee_drv.h>

/* max amount of timestamps */
#define OPTEE_BENCH_MAX_STAMPS	10
#define OPTEE_BENCH_RB_SIZE (sizeof(struct tee_time_buf) \
		+ sizeof(struct tee_time_st) * OPTEE_BENCH_MAX_STAMPS)
#define OPTEE_BENCH_DEF_PARAM		4

/* OP-TEE susbsystems ids */
#define OPTEE_BENCH_KMOD	0x20000000


/* storing timestamps */
struct tee_time_st {
	u64 cnt;	/* stores value from CNTPCT register */
	u64 addr;	/* stores value from program counter register */
	u64 src;	/* OP-TEE subsystem id */
};

/* memory layout for shared memory, where timestamps will be stored */
struct tee_time_buf {
	u64 tm_ind;		/* index of the last timestamp in stamps[] */
	struct tee_time_st stamps[];
};

#ifdef CONFIG_OPTEE_BENCHMARK
/* Reading program counter */
static inline __attribute__((always_inline)) uintptr_t read_pc(void)
{
	uintptr_t pc = NULL;
#ifdef __aarch64__
	asm volatile ("adr %0, ." : "=r" (pc));
#else
	asm volatile("mov %0, r15" : "=r"(pc));
#endif
	return pc;
}

/* Cycle counter */
static inline u64 read_ccounter(void)
{
	u64 ccounter = 0;

	asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(ccounter));
	return ccounter;
}

/* Adding timestamp to buffer */
static inline __attribute__((always_inline)) void bm_timestamp
				(struct tee_param *param, u32 source)
{
	struct tee_time_buf *timeb = NULL;
	u64 ts_i;

	if (!param || !param[OPTEE_BENCH_DEF_PARAM].u.memref.shm)
		return;

	timeb = (struct tee_time_buf *) tee_shm_get_va(
				param[OPTEE_BENCH_DEF_PARAM].u.memref.shm, 0);
	if (!timeb)
		return;
	if (timeb->tm_ind >= OPTEE_BENCH_MAX_STAMPS)
		return;

	ts_i = timeb->tm_ind++;
	timeb->stamps[ts_i].cnt = read_ccounter();
	timeb->stamps[ts_i].addr = read_pc();
	timeb->stamps[ts_i].src = source;
}
#else /* CONFIG_OPTEE_BENCHMARK */
static inline void bm_timestamp(struct tee_param *param, u32 source)
{
		;
}
#endif /* CONFIG_OPTEE_BENCHMARK */
#endif /* _OPTEE_BENCH_H */
