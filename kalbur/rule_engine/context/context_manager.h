/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file provides the interface for managing the current
 * running processes.
 */

#ifndef CONTEXT_MANAGER_H
#define CONTEXT_MANAGER_H

#include <sys/types.h>
#include <safe_hash.h>
#include <syscall_defs.h>
#include <message.h>
#include <events.h>
#include <pthread.h>

struct connections {
	struct socket_create *sock;
	struct tcp_ipv4_info *tcp4;
	struct tcp_ipv6_info *tcp6;
};

// TODO: Add open files
// TODO: Add current working directory
struct process_context {
	pthread_mutex_t ctx_lock;
	uint64_t tgid_pid;
	char comm[TASK_COMM_LEN];
	struct creds credentials;
	char *cmdline;
	char *interpreter;
	char *file_path;
	uint64_t parent_pid;
	char *parent_path;
	char parent_comm[TASK_COMM_LEN];
	struct stdio io[3];
	struct connections **open_sockets;
};

int manage_process_context(safetable_t *ht, struct message_state *ms);

#endif // CONTEXT_H
