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

static int get_event_type(struct message_state *ms)
{
	struct probe_event_header *eh =
		(struct probe_event_header *)ms->primary_data;
	if (eh == NULL)
		return CODE_FAILED;

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
		ASSERT(MESSAGE_STRING_SZ(ms) > pinfo->file.file_offset,
		       "create_process_context: string_data.size <= file_offset");
		ctx->file_path = build_filename_from_event(
			PTR_TO_STRING_DATA(ms, pinfo->file.file_offset),
			pinfo->file.path_len);

		// save cmdline
		ASSERT(MESSAGE_STRING_SZ(ms) > pinfo->args.argv_offset,
		       "create_process_context: string_data.size <= argv_offset");
		ctx->cmdline = build_cmdline(MESSAGE_STRING(ms),
					     pinfo->args.argv_offset,
					     pinfo->args.nargv);

		// save interpreter string, if present
		ASSERT(MESSAGE_STRING_SZ(ms) > pinfo->interp_str_offset,
		       "create_process_context: string_data.size <= interp_str_offset");
		interp_sz = strlen(
			PTR_TO_STRING_DATA(ms, pinfo->interp_str_offset));
		ASSERT(interp_sz < MESSAGE_STRING_SZ(ms),
		       "create_process_context: interp_sz > string_data.sz");
		ASSERT((interp_sz + pinfo->interp_str_offset) <
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

static int populate_socket_event(struct process_context *ctx,
				 struct message_state *ms)
{
	return CODE_SUCCESS;
}

static int populate_context(struct process_context *ctx,
			    struct message_state *ms, int event_type)
{
	ASSERT(ctx != NULL, "populate_context: ctx == NULL");

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
	int event_type, err;
	event_type = get_event_type(ms);
	if (event_type == CODE_FAILED) {
		err = CODE_FAILED;
		goto out;
	}

	err = populate_context(ctx, ms, event_type);
out:
	return err;
}

