#include <err.h>
#include <stdlib.h>
#include "context_manager.h"
#include "populate.h"

// The key of a process is the crc32 hash of its
// tgid_pid and comm
#define CONTEXT_KEY_LEN 2 * sizeof(uint64_t) + TASK_COMM_LEN

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

	ASSERT(ms->complete == 1, "get_process_context: ms->compelte == 0");

	eh = (struct probe_event_header *)ms->primary_data;
	ASSERT(eh != NULL, "get_process_context: eh == NULL");

	*ctx = (struct process_context *)safe_get(ht, (unsigned char *)eh,
						  CONTEXT_KEY_LEN);
	if (*ctx == NULL) {
		// Since events maybe consumed out of order, we may
		// receive an event for a process whose context is
		// not yet created. In this case we retry later.
		if (eh->syscall_nr != SYS_EXECVE) {
			err = CODE_RETRY;
			goto error;
		}
		*ctx = create_process_context(ms);
		if (*ctx == NULL) {
			err = CODE_FAILED;
			goto error;
		}

		err = try_lock_context(*ctx);
		// at this point no other thread can have access to this
		// new context, so err must be CODE_SUCCESS
		ASSERT(err == CODE_SUCCESS, "get_process_context: err != 0");

		// save context in hashtable
		err = safe_put(ht, (unsigned char *)eh, *ctx, CONTEXT_KEY_LEN);
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

int manage_process_context(safetable_t *ht, struct message_state *ms)
{
	int err;
	struct process_context *ctx;

	ASSERT(ms != NULL, "add_event_context: ms == NULL");
	ASSERT(ms->complete == 1, "add_event_context: ms->complete == 0");

	err = get_process_context(ht, ms, &ctx);
	if (err != CODE_SUCCESS)
		goto out;

	// only proceeds if context is locked.
	ASSERT(ctx != NULL, "manage_process_context: ctx == NULL");

	err = add_event_context(ctx, ms);
	unlock_context(ctx);
out:
	return err;
}
