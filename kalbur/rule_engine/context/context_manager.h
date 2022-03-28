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

// The key of a process is the crc32_hash(tgid_pid, comm)
#define CONTEXT_KEY_LEN sizeof(uint64_t) + TASK_COMM_LEN

// We explicitely copy the relevant data needed for process_context hash
// so that if struct probe_event_header changes, our hashing doesnt break
#define BUILD_PROCESS_HASH_KEY(key, eh)                                        \
	__builtin_memset(key, 0, CONTEXT_KEY_LEN);                             \
	__builtin_memcpy(key, &eh->tgid_pid, sizeof(uint64_t));                \
	__builtin_memcpy(&(key[sizeof(uint64_t)]), eh->comm,                   \
			 TYPED_MACRO(TASK_COMM_LEN, UL));

struct connections {
	struct socket_create *sock;
	struct tcp_info_t *tcp_info;
	struct connections *next;
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
	struct connections *open_sockets;
};

int manage_process_context(safetable_t *ht, safetable_t *event_counter,
			   struct message_state *ms);

#endif // CONTEXT_H
