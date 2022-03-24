/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 * 
 * This file provides the code for saving a completed message_state struct
 * into the database.
 */

#include <database.h>
#include <save_ms.h>
#include <symsearch.h>
#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#define MESSAGE_HANDLER_FUNC(name)                                             \
	static int name(sqlite3 *db, hashtable_t *ht, struct message_state *ms)

#define HANDLE_FAIL_JUMP(err)                                                  \
	do {                                                                   \
		if (err == CODE_FAILED)                                        \
			goto out;                                              \
		if (err == CODE_RETRY)                                         \
			goto rollback;                                         \
	} while (0)

static inline void set_saved(struct message_state *ms)
{
	ASSERT(ms->saved == 0, "set_saved: ms->saved != 0");
	ASSERT(ms->discard == 0, "set_saved: ms->discard != 0");
	ASSERT(ms->complete == 1, "set_saved: ms->complete != 1");

	ms->saved = 1;
}

static inline void set_discard(struct message_state *ms)
{
	ASSERT(ms->discard == 0, "set_discard: ms->discard != 0");
	ASSERT(ms->saved == 0, "set_discard: ms->saved != 0");
	ASSERT(ms->complete == 1, "set_discard: ms->complete != 1");

	ms->discard = 1;
}

static int save_mmap_helper(sqlite3 *db, hashtable_t *ht, struct proc_mmap *pm,
			    char *string_data, int event_id)
{
	struct file_info f;
	int err, file_id;

	// If pm == 0 then it is probably the struct marking
	// the end in the mmap_array.
	if (pm == 0) {
		err = CODE_SUCCESS;
		goto out;
	}

	/* In the bpf code we get file information from
  	 * security_mmap_file function, which is called with 
	 * NULL files as well (i.e. ANONYMOUS mappings). In case of NULL files,
	 * we set pathlen to zero and point fileoffset to string_data[-1]. */
	f = pm->uf;
	if (f.path_len != 0) {
		ASSERT(f.file_offset < LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE),
		       "save_mmap_helper: fileoffset out of bound\n");
		file_id = insert_file_info(db, ht, string_data, &f);
		if (ERR_NOT_SUCCESS(file_id)) {
			err = file_id;
			goto out;
		}
	} else {
		ASSERT(f.file_offset == LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE),
		       "save_mmap_helper: file_offset != PER_CPU_STR_BUFFSIZE-1");
		file_id = -1;
	}

	err = insert_mmap_info(db, ht, pm, event_id, file_id);
out:
	return err;
}

MESSAGE_HANDLER_FUNC(save_mmap_event)
{
	struct proc_mmap *pm;
	struct probe_event_header *eh;
	int err, event_id, rollback_err;

	pm = (struct proc_mmap *)ms->primary_data;
	eh = (struct probe_event_header *)pm;

	err = begin_transaction(db, ht);
	if (err != CODE_SUCCESS)
		goto out;

	event_id = insert_event(db, ht, eh);
	HANDLE_FAIL_JUMP(event_id);

	err = save_mmap_helper(db, ht, pm, MESSAGE_STRING(ms), event_id);
	HANDLE_FAIL_JUMP(err);

	err = commit_transaction(db, ht);
	if (err != CODE_SUCCESS)
		fprintf(stderr,
			"save_mmap_event: failed to commit transaction: %s\n",
			sqlite3_errmsg(db));

	HANDLE_FAIL_JUMP(err);

	return err;

rollback:
	err = CODE_RETRY;
	rollback_err = rollback_transaction(db, ht);
	ASSERT(rollback_err == CODE_SUCCESS,
	       "save_mmap_event: err (rollback_transaction) != CODE_SUCCESS");

out:
	return err;
}

MESSAGE_HANDLER_FUNC(save_execve_event)
{
	int event_id, file_id;
	int err, rollback_err;
	uint32_t mmap_cnt, i;
	struct process_info *pinfo;
	struct proc_mmap *pm;
	struct file_info f;
	struct probe_event_header *eh =
		(struct probe_event_header *)ms->primary_data;

	err = begin_transaction(db, ht);
	if (err != CODE_SUCCESS)
		goto out;

	event_id = insert_event(db, ht, eh);
	HANDLE_FAIL_JUMP(event_id);

	pinfo = (struct process_info *)ms->primary_data;
	f = pinfo->file;
	file_id = insert_file_info(db, ht, MESSAGE_STRING(ms), &f);
	HANDLE_FAIL_JUMP(file_id);

	err = insert_proc_info(db, ht, ms, event_id, file_id);
	HANDLE_FAIL_JUMP(err);

	mmap_cnt = pinfo->mmap_cnt;

	// struct proc_mmap elements start after event_header
	pm = REF_MESSAGE_MMAP_ARR(ms);

	for (i = 0; i < mmap_cnt; ++i) {
		err = save_mmap_helper(db, ht, &pm[i], MESSAGE_STRING(ms),
				       event_id);
		HANDLE_FAIL_JUMP(err);
	}

	err = commit_transaction(db, ht);
	if (err != CODE_SUCCESS)
		fprintf(stderr,
			"save_execve_event: failed to commit transaction: %s\n",
			sqlite3_errmsg(db));

	HANDLE_FAIL_JUMP(err);

	return err;

rollback:
	err = CODE_RETRY;
	rollback_err = rollback_transaction(db, ht);
	ASSERT(rollback_err == CODE_SUCCESS,
	       "save_execve: err (rollback_transaction) != CODE_SUCCESS");
out:
	return err;
}

MESSAGE_HANDLER_FUNC(save_fork_and_friends_event)
{
	int event_id, err, rollback_err;

	err = begin_transaction(db, ht);
	if (err != CODE_SUCCESS)
		goto out;

	event_id = insert_event(db, ht,
				(struct probe_event_header *)ms->primary_data);
	HANDLE_FAIL_JUMP(event_id);

	err = insert_fork_and_friends_event(db, ht, ms, event_id);
	HANDLE_FAIL_JUMP(err);

	err = commit_transaction(db, ht);
	if (err == CODE_FAILED)
		fprintf(stderr,
			"save_fork_and_friends_event: failed to commit transaction: %s\n",
			sqlite3_errmsg(db));

	HANDLE_FAIL_JUMP(err);

	return err;

rollback:
	err = CODE_RETRY;
	rollback_err = rollback_transaction(db, ht);
	ASSERT(rollback_err == CODE_SUCCESS,
	       "save_tcp_connection_event: err (rollback_transaction) != CODE_SUCCESS");
out:
	return err;
}

MESSAGE_HANDLER_FUNC(save_mprotect_event)
{
	return CODE_SUCCESS;
}

MESSAGE_HANDLER_FUNC(save_socket_create_event)
{
	int event_id, err, rollback_err;

	err = begin_transaction(db, ht);
	if (err != CODE_SUCCESS)
		goto out;

	event_id = insert_event(db, ht,
				(struct probe_event_header *)ms->primary_data);
	HANDLE_FAIL_JUMP(event_id);

	err = insert_socket_create_info(db, ht, ms, event_id);
	HANDLE_FAIL_JUMP(err);

	err = commit_transaction(db, ht);
	if (err == CODE_FAILED)
		fprintf(stderr,
			"save_socket_create_event: failed to commit transaction: %s\n",
			sqlite3_errmsg(db));

	HANDLE_FAIL_JUMP(err);

	return err;
rollback:
	err = CODE_RETRY;
	rollback_err = rollback_transaction(db, ht);
	ASSERT(rollback_err == CODE_SUCCESS,
	       "save_socket_create_event: err (rollback_transaction) != CODE_SUCCESS");

out:
	return err;
}

MESSAGE_HANDLER_FUNC(save_tcp_connection_event)
{
	int event_id, err, rollback_err;

	err = begin_transaction(db, ht);
	if (err != CODE_SUCCESS)
		goto out;

	event_id = insert_event(db, ht,
				(struct probe_event_header *)ms->primary_data);
	HANDLE_FAIL_JUMP(event_id);

	err = insert_tcp_conn_info(db, ht, ms, event_id);
	HANDLE_FAIL_JUMP(err);

	err = commit_transaction(db, ht);
	if (err == CODE_FAILED)
		fprintf(stderr,
			"save_tcp_connection_event: failed to commit transaction: %s\n",
			sqlite3_errmsg(db));

	HANDLE_FAIL_JUMP(err);

	return err;
rollback:
	err = CODE_RETRY;
	rollback_err = rollback_transaction(db, ht);
	ASSERT(rollback_err == CODE_SUCCESS,
	       "save_tcp_connection_event: err (rollback_transaction) != CODE_SUCCESS");
out:
	return err;
}

/* Need to build comprehensive list of possible callers of
 * commit_creds, in order to detect control flow hijack */
MESSAGE_HANDLER_FUNC(save_lpe_commit_creds_event)
{
	return CODE_SUCCESS;

	//	int event_id, err, rollback_err;
	//	struct cfg_integrity* cfg;
	//
	//	cfg = (struct cfg_integrity *)ms->primary_data;
	//	if (is_commit_creds_parent(cfg->caller_addr)) {
	//		err = CODE_FAILED;
	//		goto out;
	//	}
	//	printf("LPE attempt called addr: %lx. Program: %s(%lu)\n", cfg->caller_addr, cfg->eh.comm, cfg->eh.tgid_pid);
	//
	//	err = begin_transaction(db, ht);
	//	if (err != CODE_SUCCESS)
	//		goto out;
	//
	//	event_id = insert_event(db, ht, (struct probe_event_header *)ms->primary_data);
	//	HANDLE_FAIL_JUMP(event_id);
	//
	//	err = insert_lpe_info(db, ht, ms, event_id);
	//	HANDLE_FAIL_JUMP(err);
	//
	//	err = commit_transaction(db, ht);
	//	if (err == CODE_FAILED)
	//		fprintf(stderr, "save_lpe_commit_creds_event: failed to commit transaction: %s\n", sqlite3_errmsg(db));
	//
	//	HANDLE_FAIL_JUMP(err);
	//
	//	return err;
	//
	//rollback:
	//	err = CODE_RETRY;
	//	rollback_err = rollback_transaction(db, ht);
	//	ASSERT(rollback_err == CODE_SUCCESS, "save_lpe_commit_creds_event: err (rollback_transaction) != CODE_SUCCESS");
	//out:
	//	return err;
}

static int cmp_dumps(const void *d1, const void *d2)
{
	const struct dump_header *dh1, *dh2;
	dh1 = (const struct dump_header *)*(const void **)d1;
	dh2 = (const struct dump_header *)*(const void **)d2;
	uint64_t vm1 = dh1->vm_base;
	uint64_t vm2 = dh2->vm_base;

	// use comparison. subtraction can cause overflow.
	return (vm1 > vm2) - (vm1 < vm2);
}

/*
 * ---------------------
 * | dh | u8 | u8 | u8 |
 * ---------------------
*/
struct mmap_dump_data {
	struct dump_header dh;
	uint8_t first_byte;
	/* Remaining bytes */
};

static int write_mmap_dump_to_file(struct message_state *ms)
{
	char filename[128] = { 0 };
	struct probe_event_header *eh;
	struct dump_header *dh;
	int fd;
	ssize_t err;
	size_t nmemb;
	void **mmap_regions;
	struct mmap_dump_data *md;
	uint8_t *dump;

	eh = (struct probe_event_header *)ms->primary_data;
	sprintf(filename, "/opt/trapmine/dumps/%lu-%lu.dump", eh->event_time,
		eh->tgid_pid);

	fd = open(filename, O_WRONLY | O_CREAT | O_APPEND,
		  S_IRUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		return CODE_FAILED;
	}

	nmemb = MESSAGE_STRING_SZ(ms);
	qsort(MESSAGE_STRING(ms), nmemb, sizeof(void *), cmp_dumps);
	mmap_regions = MESSAGE_STRING(ms);
	// Skip zero header, so we start from i = 1;
	for (unsigned int i = 1; i < MESSAGE_STRING_SZ(ms); i++) {
		md = mmap_regions[i];
		//dh = (struct dump_header *)mmap_regions[i];
		dh = &(md->dh);

		// dump = mmap_region[i] + sizeof(struct dump_header)
		dump = &(md->first_byte);
		err = write(fd, dump, dh->dump_sz);
		if ((err < 0) || (err < (ssize_t)dh->dump_sz)) {
			err = CODE_FAILED;
			goto out;
		}
	}

	for (unsigned int i = 0; i < MESSAGE_STRING_SZ(ms); i++) {
		free(mmap_regions[i]);
		mmap_regions[i] = NULL;
	}

	err = CODE_SUCCESS;
out:
	close(fd);
	return (int)err;
}

MESSAGE_HANDLER_FUNC(save_ptrace_event)
{
	int err, event_id, rollback_err;

	err = begin_transaction(db, ht);
	if (err != CODE_SUCCESS)
		goto out;

	event_id = insert_event(db, ht,
				(struct probe_event_header *)ms->primary_data);
	HANDLE_FAIL_JUMP(event_id);

	err = insert_ptrace_event(db, ht, ms, event_id);
	HANDLE_FAIL_JUMP(err);

	err = commit_transaction(db, ht);
	if (err == CODE_FAILED)
		fprintf(stderr,
			"save_ptrace_event: failed to commit transaction: %s\n",
			sqlite3_errmsg(db));

	HANDLE_FAIL_JUMP(err);

	return err;

rollback:
	err = CODE_RETRY;
	rollback_err = rollback_transaction(db, ht);
	ASSERT(rollback_err == CODE_SUCCESS,
	       "save_ptrace_event: err (rollback_transaction) != CODE_SUCCESS");

out:
	return err;
}

MESSAGE_HANDLER_FUNC(save_kernel_module_load_info)
{
	int err, event_id, rollback_err, file_id;
	struct file_info f;
	struct kernel_module_load_info *kinfo;

	err = begin_transaction(db, ht);
	if (err != CODE_SUCCESS)
		goto out;

	event_id = insert_event(db, ht,
				(struct probe_event_header *)ms->primary_data);
	HANDLE_FAIL_JUMP(event_id);

	kinfo = (struct kernel_module_load_info *)ms->primary_data;
	f = kinfo->f;
	file_id = insert_file_info(db, ht, MESSAGE_STRING(ms), &f);
	HANDLE_FAIL_JUMP(file_id);

	err = insert_kernel_module_info(db, ht, file_id, event_id);
	HANDLE_FAIL_JUMP(err);

	err = commit_transaction(db, ht);
	if (err == CODE_FAILED)
		fprintf(stderr,
			"save_kernel_module_load_info: failed to commit transaction: %s\n",
			sqlite3_errmsg(db));

	HANDLE_FAIL_JUMP(err);

	return err;

rollback:
	err = CODE_RETRY;
	rollback_err = rollback_transaction(db, ht);
	ASSERT(rollback_err == CODE_SUCCESS,
	       "save_kernel_module_load_info: err (rollback_transaction) != CODE_SUCCESS");

out:
	return err;
}

int save_msg(sqlite3 *db, hashtable_t *hash_table, struct message_state *ms)
{
	ASSERT(ms->primary_data != NULL, "save_msg: ms->primary_data == NULL");
	struct probe_event_header *eh =
		(struct probe_event_header *)ms->primary_data;

	switch (eh->syscall_nr) {
	case (SYS_EXECVE):
		return save_execve_event(db, hash_table, ms);
	case (SYS_MMAP):
		return save_mmap_event(db, hash_table, ms);
	case (SYS_SOCKET):
		return save_socket_create_event(db, hash_table, ms);
	case (SYS_CONNECT):
		return save_tcp_connection_event(db, hash_table, ms);
	case (SYS_ACCEPT):
		return save_tcp_connection_event(db, hash_table, ms);
	case (SYS_MPROTECT):
		return save_mprotect_event(db, hash_table, ms);
	case (SYS_FORK):
		return save_fork_and_friends_event(db, hash_table, ms);
	case (SYS_VFORK):
		return save_fork_and_friends_event(db, hash_table, ms);
	case (SYS_CLONE):
		return save_fork_and_friends_event(db, hash_table, ms);
	case (SYS_PTRACE):
		return save_ptrace_event(db, hash_table, ms);
	case (SYS_FINIT_MODULE):
		return save_kernel_module_load_info(db, hash_table, ms);
	case (DUMP_MMAP_DATA):
		return write_mmap_dump_to_file(ms);
	case (LPE_COMMIT_CREDS):
		return save_lpe_commit_creds_event(db, hash_table, ms);
	default:
		fprintf(stderr, "Unexpected syscall: %d\n", eh->syscall_nr);
		return CODE_FAILED;
	}
}

