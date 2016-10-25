/*
 * Copyright (c) 2014, Linaro Limited
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

#ifndef OPTEE_BENCH_H
#define OPTEE_BENCH_H

/* max amount of timestamps */
#define TEE_BENCH_MAX_STAMPS	100
#define TEE_BENCH_RB_SIZE sizeof(struct tee_ringbuf) \
		+ sizeof(struct tee_time_st) * TEE_BENCH_MAX_STAMPS
#define TEE_BENCH_DEF_PARAM		3

/* OP-TEE susbsystems ids */
#define TEE_BENCH_KMOD		0x00000002


/* storing timestamps */
struct tee_time_st {
	u64 cnt;		/* stores value from CNTPCT register */
	u64 addr;		/* stores value from program counter register */
	u64 src; 			/* OP-TEE subsystem id */
};

/* memory layout for shared memory, where timestamps will be stored */
struct tee_ringbuf {
	u64 tm_ind;		/* index of the last timestamp in stamps[] */
	struct tee_time_st stamps[];
};



#ifdef CONFIG_OPTEE_BENCHMARK

/* Program counter */
#define TEE_BENCH_PC(src) \
	asm volatile("mov %0, r15": "=r"(src));

/* Cycle counter */
#if defined(__ARM_ARCH_7A__)
#define TEE_BENCH_TSC(src) \
	asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(src));
#else
#error Unsupported architecture!
#endif /* defined(__ARM_ARCH_7A__) */

/* Adding timestamp */
#define TEE_BENCH_ADD_TS(ringbuf_raw, source) \
	do { \
		struct tee_ringbuf *rng = (struct tee_ringbuf *)ringbuf_raw; \
		u64 ts_i = (rng->tm_ind)++; \
		TEE_BENCH_TSC(rng->stamps[ts_i].cnt); \
		TEE_BENCH_PC(rng->stamps[ts_i].addr); \
		rng->stamps[ts_i].src = source; \
	} while (0)
#else /* CONFIG_OPTEE_BENCHMARK */

#define TEE_BENCH_ADD_TS(ringbuf_raw_, source) \
	do { \
		; \
	} while (0)

#endif /* CONFIG_OPTEE_BENCHMARK */
#endif /* OPTEE_BENCH_H */
