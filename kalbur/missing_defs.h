/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 *  This file contains macro definitions from the linux kernel.
 *
 *  The linux sensor project does not link against kernel header files,
 *  in order to remain kernel agnostic. Instead it uses a combination
 *  of auto generated file containing all kernel structs (vmlinux.h) and btf
 *  files, during compilation.
 *  vmlinux.h files do not contain macro definitions, therefore, we need
 *  to redefine the kernel macros the project needs. These redefinitions
 *  are done here.
 */

#ifndef MISSING_DEFS
#define MISSING_DEFS

/* include/uapi/asm-generic/errno-base.h */
#define EBUSY 16 /* Device or resource busy */
#define EINVAL 22 /* Invalid argument */

/* include/linux/err.h */
#define IS_ERR_VALUE(x)                                                        \
	((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

/* include/uapi/linux/bpf.h */
#define BPF_ANY 0UL /* create new element or update existing */
#define BPF_NOEXIST 1UL /* create new element if it didn't exist */
#define BPF_EXIST 2UL /* update existing element */
#define BPF_F_INDEX_MASK 0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK
#define BPF_F_FAST_STACK_CMP (1ULL << 9)

/* include/uapi/linux/magic.h */
#define TMPFS_MAGIC 0x01021994

/* include/net/inet_sock.h */
#define inet_daddr sk.__sk_common.skc_daddr
#define inet_rcv_saddr sk.__sk_common.skc_rcv_saddr
#define inet_dport sk.__sk_common.skc_dport
#define inet_num sk.__sk_common.skc_num

/* include/linux/socket.h */
#define AF_INET 2 /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/

/* include/net/sock.h */
#define sk_family __sk_common.skc_family

/* include/asm-generic/page.h */
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)

/* include/uapi/linux/sched.h */
#define CLONE_PARENT_SETTID 0x00100000 /* set the TID in the parent */

/* include/linux/stringify */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvariadic-macros"
#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)
#pragma GCC diagnostic pop

/* include/uapi/linux/ptrace.h */
#define PTRACE_TRACEME 0
#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5

/* include/linux/mm.h */
#define VM_EXEC 0x00000004

#endif // MISSING_DEFS
