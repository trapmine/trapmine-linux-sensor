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
#include <stdio.h>

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
	ASSERT(IS_PROCESS_LAUNCH(pinfo->eh.syscall_nr),
	       "populate_execve_event: syscall_nr != SYS_EXECVE");

	__builtin_memcpy(&ctx->credentials, &pinfo->credentials,
			 sizeof(struct creds));
	__builtin_memcpy(ctx->io, pinfo->io, sizeof(struct stdio) * 3);

	// save parent info
	ctx->parent_pid = pinfo->ppid;
	//	__builtin_memcpy(ctx->parent_comm, pinfo->eh.parent_comm,
	//			 TYPED_MACRO(TASK_COMM_LEN, UL));

	if (MESSAGE_STRING(ms) != NULL) {
		// save filename
		ASSERT((pinfo->file.file_offset ==
			LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) ||
			       (MESSAGE_STRING_SZ(ms) >
				pinfo->file.file_offset),
		       "create_process_context: string_data.size <= file_offset");
		if (pinfo->file.file_offset !=
		    LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) {
			ctx->file_path = build_filename_from_event(
				PTR_TO_STRING_DATA(ms, pinfo->file.file_offset),
				pinfo->file.path_len);
		}

		// save cmdline
		ASSERT((pinfo->args.argv_offset ==
			LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) ||
			       (MESSAGE_STRING_SZ(ms) >
				pinfo->args.argv_offset),
		       "create_process_context: string_data.size <= argv_offset");
		ASSERT((pinfo->args.nbytes + pinfo->args.argv_offset) <=
			       MESSAGE_STRING_SZ(ms),
		       "create_process_context: args.nbytes + args.argv_offset >= MESSAGE_STRING_SZ(ms)");
		if (pinfo->args.argv_offset !=
		    LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) {
			ctx->cmdline = build_cmdline(MESSAGE_STRING(ms),
						     pinfo->args.argv_offset,
						     pinfo->args.nbytes);
		}

		// save environment
		ASSERT((pinfo->env.env_offset ==
			LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) ||
			       (MESSAGE_STRING_SZ(ms) > pinfo->env.env_offset),
		       "create_process_context: string_data.size <= argv_offset");
		ASSERT((pinfo->env.nbytes + pinfo->env.env_offset) <=
			       MESSAGE_STRING_SZ(ms),
		       "create_process_context: env.nbytes + env.env_offset >= MESSAGE_STRING_SZ(ms)");
		if (pinfo->env.env_offset !=
		    LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) {
			ctx->environment = build_env(MESSAGE_STRING(ms),
						     pinfo->env.env_offset,
						     pinfo->env.nbytes);
		}

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

static struct connections *find_connection_by_inode(struct fd *working_fd,
						    uint64_t i_ino)
{
	struct file *f;
	int err;

	err = pthread_rwlock_rdlock(&working_fd->fdlock);
	ASSERT(err == 0,
	       "find_connection_by_inode: failed to acquire read lock on fdlock");

	f = working_fd->fls;
	while (f != NULL) {
		if (f->i_ino == i_ino) {
			if (f->type == F_SOCK)
				return (struct connections *)f->obj;
		}
		f = f->next;
	}

	err = pthread_rwlock_unlock(&working_fd->fdlock);
	ASSERT(err == 0,
	       "find_connection_by_inode: failed to realse read lock");

	return NULL;
}

static int insert_socket_event(struct process_context *ctx,
			       struct message_state *ms)
{
	int err, lock_err;
	int fd;
	struct open_files *ofs;
	struct connections *c;
	struct fd *working_fd;
	tcp_info_t *tcp_info;

	ofs = ctx->files;
	ASSERT(ofs != NULL, "insert_socket_event: ofs == NULL");

	tcp_info = (tcp_info_t *)ms->primary_data;
	ASSERT(tcp_info != NULL, "insert_socket_event: tcp_info == NULL");

	// acquire read lock of fls_lock
	err = pthread_rwlock_rdlock(&ofs->fls_lock);
	ASSERT(err == 0,
	       "insert_socket_event: failed to acquire read lock on fls_lock");

	fd = tcp_info->t4.sockfd;

	// if fd is larger then ofs->fls_sz, then creation
	// event has not been received yet.
	if (fd > ofs->fls_sz) {
		err = CODE_RETRY;
		goto unlock;
	}

	working_fd = ofs->fdls[fd];
	if (working_fd == NULL) {
		err = CODE_RETRY;
		goto unlock;
	}

	c = find_connection_by_inode(working_fd, tcp_info->t4.i_ino);
	if (c == NULL) {
		err = CODE_RETRY;
		goto unlock;
	}

	c->tcp_info = (tcp_info_t *)calloc(1UL, sizeof(tcp_info_t));
	if (c->tcp_info == NULL) {
		err = CODE_FAILED;
		goto unlock;
	}

	__builtin_memcpy(c->tcp_info, tcp_info, sizeof(tcp_info_t));

	err = CODE_SUCCESS;

unlock:
	lock_err = pthread_rwlock_unlock(&ofs->fls_lock);
	ASSERT(lock_err == 0,
	       "insert_socket_event: failed to release read lock");
	return err;
}

static int realloc_fdls(struct open_files *ofs, int fd)
{
	int err, lock_err;
	unsigned long old_sz;
	unsigned long new_sz;
	struct fd **tmp;

	// take write lock on fls since we want to modify it
	err = pthread_rwlock_wrlock(&ofs->fls_lock);
	ASSERT(err == 0, "realloc_fdls: could not acquire write lock");

	tmp = ofs->fdls;
	old_sz = (unsigned long)ofs->fls_sz;

	new_sz = (unsigned int)fd * 2;
	ofs->fdls = (struct fd **)calloc(new_sz, sizeof(struct fd *));
	if (ofs->fdls == NULL) {
		err = CODE_FAILED;
		goto unlock;
	}
	ofs->fls_sz = (int)new_sz;

	memcpy(ofs->fdls, tmp, old_sz * sizeof(struct fd *));
	memset(tmp, 0, old_sz * sizeof(struct fd *));

	free(tmp);
	tmp = NULL;

	err = CODE_SUCCESS;

unlock:
	lock_err = pthread_rwlock_unlock(&ofs->fls_lock);
	ASSERT(lock_err == 0, "realloc_fdls: failed to release write lock");

	return err;
}

// This function adds a new file to the linked list of all files with
// the same fd. It acquires a write lock on it before inserting the file.
static int add_file_to_fdls(struct file **f, struct fd *working_fd)
{
	struct file *last_f;
	int err;

	// acquire write lock on fd
	err = pthread_rwlock_wrlock(&working_fd->fdlock);
	ASSERT(err == 0,
	       "add_file_to_fdls: failed to acquire write lock on fdlock");

	last_f = working_fd->fls;

	if (last_f != NULL) {
		while (last_f->next != NULL)
			last_f = last_f->next;
	} else {
		last_f = *f;
	}

	last_f->next = *f;

	err = pthread_rwlock_unlock(&working_fd->fdlock);
	ASSERT(err == 0,
	       "add_file_to_fdls: failed to realease write lock on fdlock");

	return CODE_SUCCESS;
}

static int initialize_fd(struct fd **working_fd)
{
	ASSERT(*working_fd == NULL, "initialize_fd: *working_fd != NULL");
	struct fd *f;
	int err;

	*working_fd = (struct fd *)calloc(1UL, sizeof(struct fd));
	if (*working_fd == NULL) {
		return CODE_FAILED;
	}

	f = *working_fd;
	err = pthread_rwlock_init(&(f->fdlock), NULL);
	if (err != 0) {
		fprintf(stderr, "initialize_fd: could not initialized fd: %d\n",
			err);

		free(*working_fd);
		*working_fd = NULL;
		return CODE_FAILED;
	}
	f->fls = NULL;

	return CODE_SUCCESS;
}

static int insert_new_file(struct process_context *ctx, struct file **f, int fd)
{
	struct fd *working_fd;
	struct open_files *ofs = ctx->files;
	int err, lock_err;

	ASSERT(ofs != NULL, "add_ctx_files: ofs == NULL");

	err = pthread_rwlock_rdlock(&ofs->fls_lock);
	ASSERT(err == 0,
	       "insert_new_file: failed to acquire read lock on fls_lock");

	// We need to allocate space for more files
	if (fd >= ofs->fls_sz) {
		// release read lock so we can safely take write lock
		err = pthread_rwlock_unlock(&ofs->fls_lock);
		ASSERT(err == 0,
		       "insert_new_file: failed to release read lock on fls_lock");

		// reallocate fls to double previous size
		// This will take write lock on fls before
		// allocating more space.
		err = realloc_fdls(ofs, fd);
		if (err != CODE_SUCCESS)
			goto out; // No lock taken so jump to out.

		// retake read lock on fls
		err = pthread_rwlock_rdlock(&ofs->fls_lock);
	}

	ASSERT(fd < ofs->fls_sz, "add_ctx_files: fd >= ofs->fls_sz");

	working_fd = ofs->fdls[fd];
	if (working_fd == NULL) {
		err = initialize_fd(&working_fd);
		if (err != CODE_SUCCESS)
			goto unlock;
	}

	err = add_file_to_fdls(f, working_fd);

unlock:
	lock_err = pthread_rwlock_unlock(&ofs->fls_lock);
	if (lock_err != 0) {
		fprintf(stderr, "add_ctx_file: failed to release read lock\n");
		err = CODE_FAILED;
	}

out:
	return err;
}

static int insert_socket_creation(struct process_context *ctx,
				  struct message_state *ms)
{
	ASSERT(ms != NULL, "insert_socket_creation: ms == NULL");
	ASSERT(ctx != NULL, "insert_socket_creation: ctx == NULL");
	ASSERT(ctx->files != NULL,
	       "insert_socket_creation: ctx->files == NULL");

	struct file *f;
	struct connections *c;
	struct socket_create *sock;
	struct probe_event_header *eh;
	int err;

	sock = (struct socket_create *)ms->primary_data;
	eh = (struct probe_event_header *)ms->primary_data;

	f = (struct file *)calloc(1UL, sizeof(struct file));
	if (f == NULL)
		return CODE_FAILED;

	c = (struct connections *)calloc(1UL, sizeof(struct connections));
	if (c == NULL)
		return CODE_FAILED;

	c->sock = (struct socket_create *)calloc(1UL,
						 sizeof(struct socket_create));
	if (c->sock == NULL)
		return CODE_FAILED;

	// write socket_create info into connection
	__builtin_memcpy(c->sock, sock, sizeof(struct socket_create));

	// add file information
	__builtin_memcpy(&f->eh, eh, sizeof(struct probe_event_header));
	f->type = F_SOCK;
	f->i_ino = sock->i_ino;
	f->obj = c;
	f->next = NULL;

	err = insert_new_file(ctx, &f, sock->sockfd);

	return err;
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
	} else if (IS_PROCESS_LAUNCH(event_type)) {
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

