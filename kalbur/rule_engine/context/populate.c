/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file contains code for populating the event data into the process context.
 */

#include "populate.h"
#include <err.h>
#include <string.h>
#include <helpers.h>
#include <stdlib.h>
#include <events.h>

static int get_event_type(struct message_state *ms)
{
	struct probe_event_header *eh =
		(struct probe_event_header *)ms->primary_data;
	ASSERT(eh != NULL, "get_event_type: eh == NULL");

	return eh->syscall_nr;
}

static int populate_execve_event(struct process_context *ctx,
				 struct message_state *ms)
{
	struct process_info *pinfo;
	size_t interp_sz;

	ASSERT(ctx != NULL, "populate_execve_event: ctx == NULL");
	ASSERT(ms != NULL, "populate_execve_event: ms == NULL");

	pinfo = (struct process_info *)ms->primary_data;
	ASSERT(pinfo != NULL, "populate_execve_event: pinfo == NULL");
	ASSERT(pinfo->eh.syscall_nr == SYS_EXECVE,
	       "populate_execve_event: syscall_nr != SYS_EXECVE");

	ctx->tgid_pid = pinfo->eh.tgid_pid;
	__builtin_memcpy(&ctx->credentials, &pinfo->credentials,
			 sizeof(struct creds));
	__builtin_memcpy(ctx->io, pinfo->io, sizeof(struct stdio) * 3);

	// save parent info
	ctx->parent_pid = pinfo->ppid;
	__builtin_memcpy(ctx->parent_comm, pinfo->eh.comm,
			 TYPED_MACRO(TASK_COMM_LEN, UL));

	if (MESSAGE_STRING(ms) != NULL) {
		// save filename
		ASSERT((pinfo->file.file_offset ==
			LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) ||
			       (MESSAGE_STRING_SZ(ms) >
				pinfo->file.file_offset),
		       "create_process_context: string_data.size <= file_offset");
		ctx->file_path = build_filename_from_event(
			PTR_TO_STRING_DATA(ms, pinfo->file.file_offset),
			pinfo->file.path_len);

		// save cmdline
		ASSERT((pinfo->args.argv_offset ==
			LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) ||
			       (MESSAGE_STRING_SZ(ms) >
				pinfo->args.argv_offset),
		       "create_process_context: string_data.size <= argv_offset");
		ctx->cmdline = build_cmdline(MESSAGE_STRING(ms),
					     pinfo->args.argv_offset,
					     pinfo->args.nargv);

		// save interpreter string, if present
		ASSERT((pinfo->interp_str_offset ==
			LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) ||
			       (MESSAGE_STRING_SZ(ms) >
				pinfo->interp_str_offset),
		       "create_process_context: string_data.size <= interp_str_offset");
		if (pinfo->interp_str_offset ==
		    LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE))
			interp_sz = 0;
		else
			interp_sz = strlen(PTR_TO_STRING_DATA(
				ms, pinfo->interp_str_offset));
		ASSERT(interp_sz < MESSAGE_STRING_SZ(ms),
		       "create_process_context: interp_sz > string_data.sz");
		ASSERT((interp_sz + pinfo->interp_str_offset) <=
			       PER_CPU_STR_BUFFSIZE,
		       "create_process_context: interpreter string overflow: (interp_sz + interp_str_offset) > PER_CPU_STR_BUFFSIZE");
		ctx->interpreter = calloc(interp_sz + 1, sizeof(char));
		if (ctx->interpreter != NULL) {
			strncpy(ctx->interpreter,
				PTR_TO_STRING_DATA(ms,
						   pinfo->interp_str_offset),
				interp_sz);
		}
	}

	return CODE_SUCCESS;
}

static struct connections *find_connection_by_inode(struct connections *c,
						    uint64_t i_ino)
{
	if (c == NULL)
		return NULL;

	while (c != NULL) {
		if (c->sock->i_ino == i_ino) {
			return c;
		}

		c = c->next;
	}

	ASSERT(c == NULL, "find_connection_by_inode: c != NULL");
	return c;
}

static int insert_socket_creation(struct process_context *ctx,
				  struct message_state *ms)
{
	struct connections *c, *last;
	struct socket_create *sock;
	int err;

	sock = (struct socket_create *)ms->primary_data;

	c = NULL;
	if (ctx->open_sockets == NULL) {
		// Create connection object.
		ctx->open_sockets = (struct connections *)calloc(
			1UL, sizeof(struct connections));
		if (ctx->open_sockets == NULL) {
			c = ctx->open_sockets;
			err = CODE_FAILED;
			goto error;
		}

		// Create socket_create object
		ctx->open_sockets->sock = (struct socket_create *)calloc(
			1UL, sizeof(struct socket_create));
		if (ctx->open_sockets->sock == NULL) {
			c = ctx->open_sockets;
			err = CODE_FAILED;
			goto error;
		}

		// copy socket_create object
		__builtin_memcpy(ctx->open_sockets->sock, sock,
				 sizeof(struct socket_create));

		return CODE_SUCCESS;
	}

#ifdef __DEBUG__
	// Ensure that a socket with the same inode number is not present
	// in the list. Just some invariant validation.
	ASSERT(ctx->open_sockets != NULL,
	       "insert_socket_creation: ctx->open_sockets == NULL");
	c = find_connection_by_inode(ctx->open_sockets, sock->i_ino);
	ASSERT(c == NULL,
	       "insert_socket_creation: c != NULL (socket already present)");
#endif

	// create new connection object.
	c = (struct connections *)calloc(1UL, sizeof(struct connections));
	if (c == NULL) {
		err = CODE_FAILED;
		goto error;
	}

	// create new socket_create object.
	c->sock = (struct socket_create *)calloc(1UL,
						 sizeof(struct socket_create));
	if (c->sock == NULL) {
		err = CODE_FAILED;
		goto error;
	}
	__builtin_memcpy(c->sock, sock, sizeof(struct socket_create));

	// add new connection to list
	last = ctx->open_sockets;
	ASSERT(last != NULL, "insert_socket_creation: last == NULL");
	while (last->next != NULL) {
		last = last->next;
	}

	last->next = c;

	return CODE_SUCCESS;

error:
	if (c != NULL) {
		if (c->sock != NULL) {
			free(c->sock);
		}
		free(c);
	}

	return err;
}

static int insert_socket_event(struct process_context *ctx,
			       struct message_state *ms)
{
	struct connections *c;
	tcp_info_t *tcp_info;

	tcp_info = (tcp_info_t *)ms->primary_data;

	// if we could not find the associated connection object, then this
	// event was possibly received out of order. So we will retry it later
	c = find_connection_by_inode(ctx->open_sockets, tcp_info->t4.i_ino);
	if (c == NULL)
		return CODE_RETRY;

	ASSERT(c->tcp_info == NULL, "insert_socket_event: c->tcp_info != NULL");
	c->tcp_info = (struct tcp_info_t *)calloc(1UL, sizeof(tcp_info_t));
	if (c->tcp_info == NULL)
		return CODE_FAILED;

	__builtin_memcpy(c->tcp_info, tcp_info, sizeof(tcp_info_t));

	return CODE_SUCCESS;
}

static int populate_socket_event(struct process_context *ctx,
				 struct message_state *ms)
{
	struct probe_event_header *eh;
	int err;

	eh = (struct probe_event_header *)ms->primary_data;
	ASSERT(eh != NULL, "populate_socket_event: eh == NULL");

	if (eh->syscall_nr == SYS_SOCKET) {
		err = insert_socket_creation(ctx, ms);
	} else {
		err = insert_socket_event(ctx, ms);
	}

	return err;
}

static int populate_context(struct process_context *ctx,
			    struct message_state *ms, int event_type)
{
	if (IS_SOCKET_EVENT(event_type)) {
		return populate_socket_event(ctx, ms);
	} else if (event_type == SYS_EXECVE) {
		return populate_execve_event(ctx, ms);
	} else {
		return CODE_SUCCESS;
	}
}

int add_event_context(struct process_context *ctx, struct message_state *ms)
{
	ASSERT(ctx != NULL, "add_event_context: ctx == NULL");
	ASSERT(ms != NULL, "add_event_context: ms == NULL");

	int event_type;
	event_type = get_event_type(ms);

	return populate_context(ctx, ms, event_type);
}

