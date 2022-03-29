/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * All incoming events from the kernel are placed in a generic struct, which is
 * then placed in a message list for consumption by worker threads.
 * A message may comprise of 1 or more events. The message should not be
 * consumed by the worker threads, until all constituting events have been
 * received. This file defines predicates for determing when all the events of
 * the message are received, and hence determing whether the message is ready
 * for consumption.
 */

#ifndef MESSAGE_PREDS_H
#define MESSAGE_PREDS_H
#include <message.h>
#include <err.h>

#define COMPLETE_PRED(name)                                                    \
	int name(struct message_state *);                                      \
	int name(struct message_state *ms)

COMPLETE_PRED(is_execve_complete)
{
	if ((ms->primary_data != NULL) && (MESSAGE_STRING(ms) != NULL) &&
	    (MESSAGE_MMAP(ms) != NULL))
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_mmap_complete)
{
	if ((ms->primary_data != NULL) && (MESSAGE_STRING(ms) != NULL))
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_fork_and_friends_complete)
{
	if (ms->primary_data != NULL)
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_tcp_accept_complete)
{
	if (ms->primary_data != NULL)
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_tcp_connect_complete)
{
	if (ms->primary_data != NULL)
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_socket_create_complete)
{
	if (ms->primary_data != NULL)
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_ptrace_complete)
{
	if (ms->primary_data != NULL)
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_lpe_commit_creds_complete)
{
	if (ms->primary_data != NULL)
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_mem_dump_complete)
{
	struct dump_header *dh = ms->primary_data;
	struct dump_header *data_header;
	size_t tz = 0;
	void **mmap_regions = MESSAGE_STRING(ms);
	if (dh == NULL)
		return CODE_FAILED;

	if (dh->vm_base != 0)
		return CODE_FAILED;

	for (unsigned int i = 0; i < MESSAGE_STRING_SZ(ms); ++i) {
		data_header = (struct dump_header *)mmap_regions[i];
		tz += data_header->dump_sz;
	}

	if (dh->total_sz != tz)
		return CODE_FAILED;

	return CODE_SUCCESS;
}

COMPLETE_PRED(is_module_load_complete)
{
	if ((ms->primary_data != NULL) && (MESSAGE_STRING(ms) != NULL))
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_modprobe_overwrite_complete)
{
	if (ms->primary_data != NULL)
		return CODE_SUCCESS;

	return CODE_FAILED;
}

COMPLETE_PRED(is_exit_complete)
{
	if (ms->primary_data != NULL)
		return CODE_SUCCESS;

	return CODE_FAILED;
}
#endif
