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
#define CLONE_PARENT                                                           \
	0x00008000 /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD 0x00010000 /* Same thread group */

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

/* arch/x86/include/asm/page_64_types.h */
#define THREAD_SIZE_ORDER 2
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)

#define TOP_OF_KERNEL_STACK_PADDING 0

#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#endif // MISSING_DEFS
