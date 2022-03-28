/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file contains code for manage the context of the current running processes
 */

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include "context_manager.h"
#include "populate.h"

static int try_lock_context(struct process_context *ctx)
{
	ASSERT(ctx != NULL, "try_lock_context: ctx == NULL");
	int err;
	err = pthread_mutex_trylock(&ctx->ctx_lock);
	if (err == 0) {
		return CODE_SUCCESS;
	}

	return CODE_FAILED;
}

static void unlock_context(struct process_context *ctx)
{
	ASSERT(ctx != NULL, "unlock_context: ctx == NULL");
	pthread_mutex_unlock(&ctx->ctx_lock);
}

static void free_context(struct process_context *ctx)
{
	ASSERT(ctx != NULL, "free_ctx: ctx == NULL");
	pthread_mutex_destroy(&ctx->ctx_lock);
	free(ctx);
}

static struct process_context *create_process_context(struct message_state *ms)
{
	struct process_context *ctx;
	int err;

	ctx = calloc(1UL, sizeof(struct process_context));
	if (ctx == NULL)
		return NULL;

	err = pthread_mutex_init(&ctx->ctx_lock, NULL);
	if (err != 0) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

// returns CODE_FAILED if we could not create new context, or place it in hashtable.
static int get_process_context(safetable_t *ht, struct message_state *ms,
			       struct process_context **ctx)
{
	int err;
	struct probe_event_header *eh;
	unsigned char key[CONTEXT_KEY_LEN];

	ASSERT(IS_MS_COMPLETE(ms) == 1,
	       "get_process_context: ms->compelte == 0");

	eh = (struct probe_event_header *)ms->primary_data;
	ASSERT(eh != NULL, "get_process_context: eh == NULL");

	BUILD_PROCESS_HASH_KEY(key, eh);

	*ctx = (struct process_context *)safe_get(ht, key, CONTEXT_KEY_LEN);
	if (*ctx == NULL) {
		// Since events maybe consumed out of order, we may
		// receive an event for a process whose context is
		// not yet created. In this case we retry later.
		if (!((eh->syscall_nr == SYS_EXECVE) ||
		      IS_FORK_OR_FRIENDS(eh->syscall_nr))) {
			err = CODE_RETRY;
			goto error;
		}

		// create process_context struct. Return CODE_FAILED
		// in case of failiure, which causes this message_state
		// not to trigger rules
		*ctx = create_process_context(ms);
		if (*ctx == NULL) {
			err = CODE_FAILED;
			goto error;
		}

		err = try_lock_context(*ctx);
		// at this point no other thread can have access to this
		// new context, so err must be CODE_SUCCESS
		ASSERT(err == CODE_SUCCESS, "get_process_context: err != 0");

		// save context in hashtable. If failed to save process_context
		// return CODE_FAILED, and destroy newly created struct
		err = safe_put(ht, key, *ctx, CONTEXT_KEY_LEN);
		if (err != CODE_SUCCESS) {
			err = CODE_FAILED;
			goto delete_ctx;
		}

		return CODE_SUCCESS;
	}

	// attempt to lock context for modification
	err = try_lock_context(*ctx);
	if (err == CODE_FAILED) {
		*ctx = NULL;
		// If we failed to lock the context for use then it must be
		// in use by another thread. Try another time.
		err = CODE_RETRY;
		goto error;
	}

	return CODE_SUCCESS;

error:
	return err;

	//unlock:
	//	unlock_context(*ctx);
	//	return err;

delete_ctx:
	unlock_context(*ctx);
	free_context(*ctx);
	return err;
}

static void destroy_process_connections(struct process_context *ctx)
{
	struct connections *conns, *tmp;

	conns = ctx->open_sockets;
	while (conns != NULL) {
		tmp = conns->next;
		if (conns->sock != NULL)
			free(conns->sock);
		if (conns->tcp_info != NULL)
			free(conns->tcp_info);

		free(conns);
		conns = tmp;
	}

	ctx->open_sockets = NULL;
}

static int destroy_process_context(struct process_context *ctx)
{
	int err;
	if (ctx->cmdline != NULL) {
		free(ctx->cmdline);
		ctx->cmdline = NULL;
	}
	if (ctx->interpreter != NULL) {
		free(ctx->interpreter);
		ctx->interpreter = NULL;
	}
	if (ctx->file_path != NULL) {
		free(ctx->file_path);
		ctx->file_path = NULL;
	}
	if (ctx->parent_path != NULL) {
		free(ctx->parent_path);
		ctx->parent_path = NULL;
	}

	destroy_process_connections(ctx);

	unlock_context(ctx);
	err = pthread_mutex_destroy(&ctx->ctx_lock);
	if (err != 0)
		return CODE_RETRY;

	free(ctx);
	ctx = NULL;

	return CODE_SUCCESS;
}

static bool is_fully_consumed(safetable_t *event_counter,
			      struct message_state *ms)
{
	struct probe_event_header *eh;
	unsigned char key[CONTEXT_KEY_LEN];
	int64_t ecnt;

	eh = (struct probe_event_header *)ms->primary_data;
	ASSERT(eh != NULL, "is_fully_consumed: eh == NULL");

	BUILD_PROCESS_HASH_KEY(key, eh);
	ecnt = (int64_t)safe_get(event_counter, key, CONTEXT_KEY_LEN);
	ASSERT(ecnt != 0, "is_fully_consumed: ecnt == 0");

	// If the event count for this process is 1, then only
	// the final exit event remains to be consumed. If so, then
	// we must delete this context
	if (ecnt == 1) {
		return true;
	}

	return false;
}

static bool is_end_of_life_event(struct message_state *ms)
{
	struct probe_event_header *eh;

	eh = (struct probe_event_header *)ms->primary_data;
	ASSERT(eh != NULL, "is_end_of_life_event: eh == NULL");

	if (IS_EXIT_EVENT(eh->syscall_nr)) {
		return true;
	}

	return false;
}

static int detect_and_handle_end_of_life(safetable_t *event_counter,
					 struct message_state *ms,
					 struct process_context *ctx)
{
	int err;
	if (is_end_of_life_event(ms)) {
		if (is_fully_consumed(event_counter, ms)) {
			// If this is an exit event, and there are no remaining
			// events for this process, we must delete the context.
			err = destroy_process_context(ctx);
		} else {
			// If this is an exit event, and there are other events
			// for this process remaining to be consumed ,
			// we return CODE_RETRY so engine retries for this ms.
			err = CODE_RETRY;
		}
	} else {
		err = CODE_FAILED;
	}

	return err;
}

int manage_process_context(safetable_t *ht, safetable_t *event_counter,
			   struct message_state *ms)
{
	int err;
	struct process_context *ctx;

	ASSERT(ms != NULL, "add_event_context: ms == NULL");
	ASSERT(IS_MS_COMPLETE(ms) == 1, "add_event_context: ms->complete == 0");

	// If ht == NULL, we return CODE_FAILED which causes
	// ms to transition to MS_IGNORE_CTX_SAVE state.
	// This means it wont have rules applied to it
	if (ht == NULL) {
		fprintf(stderr,
			"manage_process_context: hashtable for process context is NULL\n");

		err = CODE_FAILED;
		goto error;
	}

	// get_process_context only locks the context struct if
	// successfuly acquire. If CODE_RETRY or CODE_FAILED context
	// is not locked, so we can directly return
	err = get_process_context(ht, ms, &ctx);
	if (err != CODE_SUCCESS)
		goto error;

	// only proceed if context is locked.
	ASSERT(ctx != NULL, "manage_process_context: ctx == NULL");

	// if exit event, then see if we can remove process context
	err = detect_and_handle_end_of_life(event_counter, ms, ctx);
	// if err is CODE_SUCCESS, then context removed. We return
	// CODE_FAILED to transition engine to MS_IGNORE_CTX_SAVE,
	// since we do not trigger any rules for exit events.
	if (err == CODE_SUCCESS) {
		err = CODE_FAILED;
		goto error;
	} else if (err == CODE_RETRY) {
		// if err is CODE_RETRY, then either context desctruction
		// needs to be retried, or all events for this process
		// havent been consumed. So we goto out, to unlock context
		// and retry later.
		goto out;
	}
	// if CODE_FAILED then not exit event and we go on to populate
	// context.

	err = add_event_context(ctx, ms);
out:
	unlock_context(ctx);
error:
	return err;
}
