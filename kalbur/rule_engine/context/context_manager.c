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
#include <string.h>
#include "populate.h"

static void acquire_write_lock(struct process_context *ctx)
{
	ASSERT(ctx != NULL, "try_lock_context: ctx == NULL");
	int err;

	err = pthread_rwlock_wrlock(&ctx->ctx_lock);
	ASSERT(err == 0,
	       "acquire_write_lock: failed to acquire write lock on ctx");
}

static void acquire_read_lock(struct process_context *ctx)
{
	ASSERT(ctx != NULL, "try_lock_context: ctx == NULL");
	int err;

	err = pthread_rwlock_rdlock(&ctx->ctx_lock);
	ASSERT(err == 0,
	       "acquire_read_lock: failed to acquire read lock lock on ctx");
}

static void release_rwlock(struct process_context *ctx)
{
	ASSERT(ctx != NULL, "release_rwlock: ctx == NULL");
	int err;

	err = pthread_rwlock_unlock(&ctx->ctx_lock);
	ASSERT(err == 0, "release_rwlock: failed to release read lock on ctx");
}

static void free_open_files(struct process_context *ctx)
{
	ASSERT(ctx != NULL, "free_open_files: ctx == NULL");
	int err;

	if (ctx->files == NULL)
		return;

	err = pthread_rwlock_destroy(&(ctx->files->fls_lock));
	ASSERT(err == 0, "free_open_files: failed to destory lock fls_lock");
	free(ctx->files->fdls);
	ctx->files->fdls = NULL;
	free(ctx->files);
	ctx->files = NULL;
}

static void free_context(struct process_context *ctx)
{
	ASSERT(ctx != NULL, "free_ctx: ctx == NULL");
	pthread_rwlock_destroy(&ctx->ctx_lock);

	free_open_files(ctx);
	free(ctx);
}

static struct process_context *create_process_context(void)
{
	struct process_context *ctx;
	int err;

	ctx = calloc(1UL, sizeof(struct process_context));
	if (ctx == NULL)
		return NULL;

	err = pthread_rwlock_init(&ctx->ctx_lock, NULL);
	if (err != 0) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

static struct open_files *initialize_open_files(void)
{
	struct open_files *of;
	int err;

	of = (struct open_files *)calloc(1UL, sizeof(struct open_files));
	if (of == NULL)
		return NULL;

	err = pthread_rwlock_init(&of->fls_lock, NULL);
	if (err != 0)
		goto free_of;

	// acquire write lock on fls_lock to prevent use before initialization
	err = pthread_rwlock_wrlock(&of->fls_lock);
	ASSERT(err == 0, "initialize_open_files: could not acquire write lock");

	of->fdls = (struct fd **)calloc(TYPED_MACRO(INIT_FDTABLE_SZ, UL),
					sizeof(struct fd *));
	if (of->fdls == NULL)
		goto error;

	of->fls_sz = INIT_FDTABLE_SZ;

	err = pthread_rwlock_unlock(&of->fls_lock);
	ASSERT(err == 0, "initialize_open_files: could not release write lock");

	return of;

error:
	err = pthread_rwlock_unlock(&of->fls_lock);
	ASSERT(err == 0, "initialize_open_files: could not release write lock");

	err = pthread_rwlock_destroy(&of->fls_lock);
	ASSERT(err == 0,
	       "initialize_open_files: failed to destroy rw lock on error");
free_of:
	free(of);
	of = NULL;

	return NULL;
}

static int initialize_context_with_event(struct process_context *ctx,
					 struct probe_event_header *eh)
{
	ASSERT(ctx != NULL, "initialize_context_with_event: ctx == NULL");
	ASSERT(eh != NULL, "initialize_context_with_event: eh == NULL");

	ctx->tgid_pid = eh->tgid_pid;
	__builtin_memcpy(ctx->comm, eh->comm, TYPED_MACRO(TASK_COMM_LEN, UL));

	ctx->files = initialize_open_files();
	if (ctx->files == NULL)
		return CODE_FAILED;

	return CODE_SUCCESS;
}

static int get_process_context(safetable_t *ht, struct message_state *ms,
			       struct process_context **ctx)
{
	int err;
	struct probe_event_header *eh;
	unsigned char key[CONTEXT_KEY_LEN];

	ASSERT(IS_MS_COMPLETE(ms) != 0,
	       "get_process_context: ms->compelte == 0");

	eh = (struct probe_event_header *)ms->primary_data;
	ASSERT(eh != NULL, "get_process_context: eh == NULL");

	BUILD_PROCESS_HASH_KEY(key, eh);

	*ctx = (struct process_context *)safe_get(ht, key, CONTEXT_KEY_LEN);
	if (*ctx == NULL) {
		if (IS_EXIT_EVENT(eh->syscall_nr))
			return CODE_FAILED;

		// create process_context struct. Return CODE_FAILED
		// in case of failiure, which causes this message_state
		// not to trigger rules
		*ctx = create_process_context();
		if (*ctx == NULL) {
			err = CODE_FAILED;
			goto error;
		}

		err = initialize_context_with_event(*ctx, eh);
		if (err != CODE_SUCCESS)
			goto delete_ctx;

		// save context in hashtable. If failed to save process_context
		// return CODE_FAILED, and destroy newly created struct
		err = safe_put(ht, key, *ctx, CONTEXT_KEY_LEN);
		if (err != CODE_SUCCESS) {
			err = CODE_FAILED;
			goto delete_ctx;
		}
	}

	if (IS_PROCESS_LAUNCH(eh->syscall_nr))
		acquire_write_lock(*ctx);
	else
		acquire_read_lock(*ctx);

	return CODE_SUCCESS;

error:
	return err;

delete_ctx:
	release_rwlock(*ctx);
	free_context(*ctx);
	return err;
}

static void destroy_connections_obj(struct connections *c)
{
	free(c->sock);
	c->sock = NULL;
	free(c->tcp_info);
	c->tcp_info = NULL;
}

static void destroy_file_obj(void *obj, enum FILE_TYPE type)
{
	if (type == F_SOCK)
		destroy_connections_obj((struct connections *)obj);
}

static void destroy_fd(struct fd *fd)
{
	struct file *f, *tmp;
	int err;

	if (fd == NULL)
		return;

	f = fd->fls;
	while (f != NULL) {
		tmp = f;
		f = f->next;
		destroy_file_obj(tmp->obj, f->type);

		free(tmp);
		tmp = NULL;
	}

	err = pthread_rwlock_destroy(&fd->fdlock);
	ASSERT(err == 0, "destroy_fd: could not destroy fdlock");
}

static void destroy_process_files(struct process_context *ctx)
{
	int err;
	struct open_files *files = ctx->files;

	if (files == NULL)
		return;

	for (int i = 0; i < files->fls_sz; i++) {
		destroy_fd(files->fdls[i]);
		files->fdls[i] = 0;
	}

	files->fls_sz = 0;

	err = pthread_rwlock_destroy(&files->fls_lock);
	ASSERT(err == 0, "destroy_process_files: could not destroy fls_lock");

	free(files);

	ctx->files = NULL;
}

static int destroy_process_context(struct process_context *ctx)
{
	ASSERT(ctx != NULL, "destroy_process_context: ctx == NULL");
	int err;
	if (ctx->cmdline != NULL) {
		free(ctx->cmdline);
		ctx->cmdline = NULL;
	}
	if (ctx->environment != NULL) {
		free(ctx->environment);
		ctx->environment = NULL;
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

	destroy_process_files(ctx);

	// release write lock
	release_rwlock(ctx);

	err = pthread_rwlock_destroy(&ctx->ctx_lock);
	ASSERT(err == 0, "destroy_process_context: failed to destory rwlock");

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
	ASSERT(IS_EXIT_EVENT(eh->syscall_nr),
	       "is_fully_consumed: not exit event");

	BUILD_PROCESS_HASH_KEY(key, eh);
	ecnt = (int64_t)safe_get(event_counter, key, CONTEXT_KEY_LEN);

	//ASSERT(ecnt != 0, "is_fully_consumed: ecnt == 0");

	// If the event count for this process is 1, then only
	// the final exit event remains to be consumed. If so, then
	// we must delete this context
	if (ecnt == 1) {
		return true;
	}

	return false;
}
static void print_context(struct process_context *ctx)
{
	//struct connections *c;

	printf("[%lu] {\n", ctx->tgid_pid);
	printf("\tpid: %lu\n", ctx->tgid_pid >> 32);
	printf("\tcomm: %s\n", ctx->comm);
	printf("\tparent comm: %s\n", ctx->parent_comm);
	printf("\tparent tgid_pid: %lu\n", ctx->parent_pid);
	printf("\tcredentials {\n");
	printf("\t\tuid: %u\n", ctx->credentials.uid);
	printf("\t\tgid: %u\n", ctx->credentials.gid);
	printf("\t\teuid: %u\n", ctx->credentials.euid);
	printf("\t\tegid: %u\n", ctx->credentials.egid);
	printf("\t}\n");
	printf("\tcmdline: %s\n", ctx->cmdline);
	printf("\tenvironment: %s\n", ctx->environment);
	printf("\tinterpreter: %s\n", ctx->interpreter);
	printf("\tfile path: %s\n", ctx->file_path);
	//printf("\tconnections: {\n");

	//c = ctx->open_sockets;
	//while (c != NULL) {
	//	printf("\t\tinode num: %lu\n", c->sock->i_ino);
	//	printf("\t\ttype: %d\n", c->sock->family);
	//	printf("\t\tfamily: %d\n", c->sock->type);
	//	printf("\t\tprotocol: %d\n", c->sock->protocol);
	//	c = c->next;
	//}
	//printf("\t}\n");
	printf("}\n");
}

static int detect_and_handle_end_of_life(safetable_t *event_counter,
					 safetable_t *ht,
					 struct message_state *ms,
					 struct process_context *ctx)
{
	unsigned char key[CONTEXT_KEY_LEN];
	struct probe_event_header *eh;
	void *del_ctx;
	int err;

	eh = (struct probe_event_header *)ms->primary_data;
	ASSERT(eh != NULL, "is_end_of_life_event: eh == NULL");

	if (IS_EXIT_EVENT(eh->syscall_nr)) {
		if (is_fully_consumed(event_counter, ms)) {
			BUILD_PROCESS_HASH_KEY(key, eh);

			// If this is an exit event, and there are no remaining
			// events for this process, we must delete the context.
			del_ctx = safe_delete(ht, key, CONTEXT_KEY_LEN);
			ASSERT(del_ctx != NULL,
			       "detect_and_handle_end_of_life: del_ctx == NULL");
#ifdef __DEBUG__
			//		print_context(ctx);
			printf("exiting process: %lu: %s\n", ctx->tgid_pid,
			       ctx->comm);
//			printf("\n");
#endif

			ASSERT(del_ctx == ctx,
			       "detect_and_handle_end_of_life: del_ctx != ctx");

			// release read lock
			release_rwlock(ctx);

			// acquire write lock
			acquire_write_lock(ctx);

			// this function destroy the read write lock
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
	ASSERT(IS_MS_COMPLETE(ms) != 0, "add_event_context: ms->complete == 0");

	// If ht == NULL, we return CODE_FAILED which causes
	// ms to transition to MS_IGNORE_CTX_SAVE state.
	// This means it wont have rules applied to it
	if (ht == NULL) {
		fprintf(stderr,
			"manage_process_context: hashtable for process context is NULL\n");

		err = CODE_FAILED;
		goto error;
	}

#ifdef __DEBUG__
	struct probe_event_header *eh;
	eh = ms->primary_data;
#endif

	// get_process_context acquire write lock if a new context is created.
	// Otherwise it acquires a readlock if we want to work with already
	// created context
	err = get_process_context(ht, ms, &ctx);
	if (err != CODE_SUCCESS)
		goto error;

	// only proceed if context is locked.
	ASSERT(ctx != NULL, "manage_process_context: ctx == NULL");

	// if exit event, then see if we can remove process context
	err = detect_and_handle_end_of_life(event_counter, ht, ms, ctx);
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
#ifdef __DEBUG__
	if (IS_PROCESS_LAUNCH(eh->syscall_nr)) {
		if (err == CODE_SUCCESS) {
			printf("[%d] generated context for: %lu : %s\n",
			       eh->syscall_nr, eh->tgid_pid, eh->comm);
		} else if (err != CODE_SUCCESS) {
			printf("[%d] failed to generate context for: %lu: %s\n",
			       eh->syscall_nr, eh->tgid_pid, eh->comm);
		}
	}
#endif

out:
	release_rwlock(ctx);
error:
	return err;
}
