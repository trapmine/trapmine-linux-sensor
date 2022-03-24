#ifndef CONTEXT_H
#define CONTEXT_H

#include <sys/types.h>
#include <missing_defs.h>
#include <safe_hash.h>
#include <message.h>
#include <events.h>
#include <pthread.h>

struct connections {
	struct socket_create *sock;
	struct tcp_ipv4_info *tcp4;
	struct tcp_ipv6_info *tcp6;
};

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
