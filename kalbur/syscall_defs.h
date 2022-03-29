/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file defines macros for syscall numbers.
 * Moreover, it defines helper macros for checking if the
 * event type (syscall or some other event) are to be handled
 * or ignored.
 */

#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H

#include <syscall.h>
#define SYS_EXECVE __NR_execve
#define SYS_MMAP __NR_mmap
#define SYS_FORK __NR_fork
#define SYS_VFORK __NR_vfork
#define SYS_CLONE __NR_clone
#define SYS_MPROTECT __NR_mprotect
#ifdef SYS_SOCKET
#undef SYS_SOCKET
#endif
#define SYS_SOCKET __NR_socket
#ifdef SYS_CONNECT
#undef SYS_CONNECT
#endif
#define SYS_CONNECT __NR_connect
#ifdef SYS_ACCEPT
#undef SYS_ACCEPT
#endif
#define SYS_ACCEPT __NR_accept
#define SYS_PTRACE __NR_ptrace
#define SYS_FINIT_MODULE __NR_finit_module

#define DUMP_MMAP_DATA -1
#define LPE_COMMIT_CREDS -2
#define MODPROBE_OVERWRITE -3
#define EXIT_EVENT -4

#define IS_EXIT_EVENT(syscall) (syscall == EXIT_EVENT)

#define IS_SOCKET_EVENT(syscall)                                               \
	((syscall == SYS_SOCKET) || (syscall == SYS_CONNECT) ||                \
	 (syscall == SYS_ACCEPT))

#define IS_FORK_OR_FRIENDS(syscall)                                            \
	((syscall == SYS_FORK) || (syscall == SYS_VFORK) ||                    \
	 (syscall == SYS_CLONE))

#define IS_EVENT_HANDLED(syscall)                                              \
	((IS_SYSCALL_HANDLED(syscall)) || (syscall == DUMP_MMAP_DATA) ||       \
	 (syscall == LPE_COMMIT_CREDS) || (syscall == MODPROBE_OVERWRITE) ||   \
	 (syscall == EXIT_EVENT))

#define IS_SYSCALL_HANDLED(syscall)                                            \
	((IS_FORK_OR_FRIENDS(syscall)) || (syscall == SYS_EXECVE) ||           \
	 (syscall == SYS_MMAP) || (syscall == SYS_MPROTECT) ||                 \
	 (syscall == SYS_CONNECT) || (syscall == SYS_ACCEPT) ||                \
	 (syscall == SYS_SOCKET) || (syscall == SYS_PTRACE) ||                 \
	 (syscall == SYS_FINIT_MODULE))

#endif // SYSCALL_DEFS_H
