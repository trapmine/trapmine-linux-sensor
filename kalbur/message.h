/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file provides the interface for handling events coming from the kernel.
 * All incoming events from the kernel are placed in a generic struct, which is
 * then placed in a message list for consumption by worker threads.
 * This file provides the interface for constructing and linking these events.
 */

#ifndef MESSAGE_H
#define MESSAGE_H
#include <pthread.h>
#include <events.h>
#include <syscall_defs.h>
#include <stdint.h>
#include <stdbool.h>

struct message_state;

#define GET_STRUCT_FIELD(ptr, type, field) ((type *)ptr)->field

#define MESSAGE_STRING(ms)                                                     \
	(GET_STRUCT_FIELD(ms, struct message_state, str_data).string)

#define MESSAGE_STRING_SZ(ms)                                                  \
	(GET_STRUCT_FIELD(ms, struct message_state, str_data).str_size)

#define PTR_TO_STRING_DATA(ms, off) (&(((char *)MESSAGE_STRING(ms))[off]))

#define MESSAGE_MMAP(ms)                                                       \
	(GET_STRUCT_FIELD(ms, struct message_state, mmap_data).mmap)

#define MESSAGE_MMAP_SZ(ms)                                                    \
	(GET_STRUCT_FIELD(ms, struct message_state, mmap_data).mmap_size)

/*
 * ------------------------
 * | eh | pm1 | pm2 | pm3 |
 * ------------------------
*/
struct mmap_dump_fmt {
	struct probe_event_header eh;
	struct proc_mmap mmap;
	/* Rest of the proc_mmap structures */
};
#define REF_MESSAGE_MMAP_ARR(ms)                                               \
	&(((struct mmap_dump_fmt *)MESSAGE_MMAP(ms))->mmap)

#define EVENT_HEADER_EQ(eh_incoming, eh_matching)                              \
	(GET_STRUCT_FIELD(eh_incoming, struct probe_event_header,              \
			  event_time) ==                                       \
	 GET_STRUCT_FIELD(eh_matching, struct probe_event_header,              \
			  event_time)) &&                                      \
		(GET_STRUCT_FIELD(eh_incoming, struct probe_event_header,      \
				  tgid_pid) ==                                 \
		 GET_STRUCT_FIELD(eh_matching, struct probe_event_header,      \
				  tgid_pid))

#define SYSCALL_PRIMARY_STRUCT_SZ(copy, syscall)                               \
	do {                                                                   \
		if (syscall == SYS_EXECVE)                                     \
			copy = sizeof(struct process_info);                    \
		else if (syscall == SYS_MMAP)                                  \
			copy = sizeof(struct proc_mmap);                       \
		else if (syscall == SYS_CONNECT)                               \
			copy = sizeof(tcp_info_t);                             \
		else if (syscall == SYS_ACCEPT)                                \
			copy = sizeof(tcp_info_t);                             \
		else if (syscall == SYS_SOCKET)                                \
			copy = sizeof(struct socket_create);                   \
		else if (IS_FORK_OR_FRIENDS(syscall))                          \
			copy = sizeof(struct child_proc_info);                 \
		else if (syscall == LPE_COMMIT_CREDS)                          \
			copy = sizeof(struct cfg_integrity);                   \
		else if (syscall == SYS_PTRACE)                                \
			copy = sizeof(struct ptrace_event_info);               \
		else if (syscall == SYS_FINIT_MODULE)                          \
			copy = sizeof(struct kernel_module_load_info);         \
		else if (syscall == MODPROBE_OVERWRITE)                        \
			copy = sizeof(struct modprobe_overwrite);              \
		else                                                           \
			ASSERT(0 == 1,                                         \
			       "SYSCALL_PRIMARY_STRUCT: Invalid syscall");     \
	} while (0)

#define FREEABLE(ms) ((ms->saved == 1) || (ms->discard == 1))

#define TO_GC(ms) ((ms != NULL) && (FREEABLE(ms)))

typedef bool (*message_complete_predicate)(struct message_state *);

struct message_state {
	pthread_mutex_t message_state_lock;
	void *primary_data;
	message_complete_predicate pred;
	struct {
		void *string;
		uint32_t str_size;
	} str_data;
	struct {
		void *mmap;
		uint32_t mmap_size;
	} mmap_data;
	struct message_state *next_msg;
	struct message_state
		*prev_msg; // Needed inorder to link and unlink new messages
	struct message_state
		*next_gc; // Optimization to quickly find struct to free
	int cpu;
	int complete;
	int saved;
	int discard;
};

int construct_message_state(struct message_state *ms,
			    struct probe_event_header *eh_local, void *data,
			    unsigned int size);
int is_legal_event(struct probe_event_header *eh);
struct message_state *allocate_message_struct(int syscall, int cpu);
struct probe_event_header *get_event_header(struct message_state *ms);
void delete_message(struct message_state **ms);

#endif // MESSAGE_H
