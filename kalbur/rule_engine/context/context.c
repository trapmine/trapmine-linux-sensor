#include <context.h>
#include <err.h>
#include <syscall_defs.h>
#include <string.h>
#include <helpers.h>
#include <stdlib.h>

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

static int add_event_context(struct process_context *ctx,
			     struct message_state *ms)
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
