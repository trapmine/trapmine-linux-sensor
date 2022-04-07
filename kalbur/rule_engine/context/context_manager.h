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

// The key of a process is the crc32_hash(syscall_nr, tgid_pid, comm)
#define CONTEXT_KEY_LEN (sizeof(uint64_t) + TASK_COMM_LEN)

// We explicitely copy the relevant data needed for process_context hash
// so that if struct probe_event_header changes, our hashing doesnt break
#define BUILD_PROCESS_HASH_KEY(key, eh)                                        \
	__builtin_memset(key, 0, CONTEXT_KEY_LEN);                             \
	__builtin_memcpy(key, &eh->tgid_pid, sizeof(uint64_t));                \
	__builtin_memcpy(&(key[sizeof(uint64_t)]), eh->comm,                   \
			 TYPED_MACRO(TASK_COMM_LEN, UL));

#define INIT_FDTABLE_SZ 20

struct connections {
	struct socket_create *sock;
	tcp_info_t *tcp_info;
};

enum FILE_TYPE { F_SOCK, F_REG };

struct file {
	struct probe_event_header eh;
	enum FILE_TYPE type;
	uint64_t i_ino;
	void *obj;
	struct file *next;
};

struct fd {
	pthread_rwlock_t fdlock;
	struct file *fls;
};

struct open_files {
	pthread_rwlock_t fls_lock;
	int fls_sz;
	struct fd **fdls;
};

// TODO: Add open files
// TODO: Add current working directory
struct process_context {
	pthread_rwlock_t ctx_lock;
	uint64_t tgid_pid;
	char comm[TASK_COMM_LEN];
	struct creds credentials;
	char *cmdline;
	char *environment;
	char *interpreter;
	char *file_path;
	uint64_t parent_pid;
	char *parent_path;
	char parent_comm[TASK_COMM_LEN];
	struct stdio io[3];
	struct open_files *files;
};

int manage_process_context(safetable_t *ht, safetable_t *event_counter,
			   struct message_state *ms);

#endif // CONTEXT_H
