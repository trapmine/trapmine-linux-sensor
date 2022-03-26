/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file contains code for manage the context of the current running processes
 */

#include <err.h>
#include <stdlib.h>
#include "context_manager.h"
#include "populate.h"
#include <stdio.h>

// The key of a process is the crc32_hash(tgid_pid, comm)
#define CONTEXT_KEY_LEN sizeof(uint64_t) + TASK_COMM_LEN

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

// We explicitely copy the relevant data needed for process_context hash
// so that if struct probe_event_header changes, our hashing doesnt break
#define BUILD_PROCESS_HASH_KEY(key, eh)                                        \
	__builtin_memset(key, 0, CONTEXT_KEY_LEN);                             \
	__builtin_memcpy(key, &eh->tgid_pid, sizeof(uint64_t));                \
	__builtin_memcpy(&(key[sizeof(uint64_t)]), eh->comm,                   \
			 TYPED_MACRO(TASK_COMM_LEN, UL));

// returns CODE_FAILED if we could not create new context, or place it in hashtable.
static int get_process_context(safetable_t *ht, struct message_state *ms,
			       struct process_context **ctx)
{
	int err;
	struct probe_event_header *eh;
	unsigned char key[CONTEXT_KEY_LEN];

	ASSERT(ms->complete == 1, "get_process_context: ms->compelte == 0");

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
int manage_process_context(safetable_t *ht, struct message_state *ms)
{
	int err;
	struct process_context *ctx;

	ASSERT(ms != NULL, "add_event_context: ms == NULL");
	ASSERT(ms->complete == 1, "add_event_context: ms->complete == 0");

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

	// only proceeds if context is locked.
	ASSERT(ctx != NULL, "manage_process_context: ctx == NULL");

	if (is_end_of_life_event(ms)) {
		// If this is an exit event, we return CODE_FAILED
		// so engine transitions ms to MS_IGNORE_CTX_SAVE.
		// We do not want to trigger rules for process exit.
		//
		// Return to out target, because context needs to be
		// unlocked.
		err = CODE_FAILED;
		goto out;
	}

	err = add_event_context(ctx, ms);
out:
	unlock_context(ctx);
error:
	return err;
}
