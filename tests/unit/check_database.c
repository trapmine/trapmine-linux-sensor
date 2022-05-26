/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#include <events.h>
#include <stdio.h>
#include <err.h>
#include <check.h>
#include <helpers.h>
#include <database.h>
#include <notifier.h>
#include <stdlib.h>
#include <syscall_defs.h>
#include <schema.h>
#include <sys/socket.h>

#define TMP_DB "/tmp/test_db"
#define TMP_WAL TMP_DB "-wal"
#define TMP_SHM TMP_DB "-shm"

#define REMOVE_DB                                                              \
	do {                                                                   \
		remove(TMP_DB);                                                \
		remove(TMP_WAL);                                               \
		remove(TMP_SHM);                                               \
	} while (0)

sqlite3 *db;
hashtable_t *ht;
void create_database()
{
	int err;

	err = initialize_database(TMP_DB);
	ck_assert(err == CODE_SUCCESS);

	err = create_connection(TMP_DB, &db, 0);
	ck_assert(err == CODE_SUCCESS);
}

void delete_database()
{
	close_database(db);

	REMOVE_DB;
}

void create_hashtable()
{
	ht = init_hashtable();
	ck_assert_ptr_nonnull(ht);
}

void delete_hashtable()
{
	delete_table(ht);
}

void pre__insert()
{
	int err;

	err = prepare_sql(db, ht);
	ck_assert(err == CODE_SUCCESS);

	err = begin_transaction(db, ht);
	ck_assert(err == CODE_SUCCESS);
}

void post__insert()
{
	int err;

	err = commit_transaction(db, ht);
	ck_assert(err == CODE_SUCCESS);
}

START_TEST(test_create_connection)
{
	sqlite3 *db;
	int err;

	err = create_connection("db:mem", &db, 1);
	ck_assert(err == CODE_SUCCESS);

	close_database(db);
}
END_TEST

START_TEST(test_prepare_sql)
{
	hashtable_t *hash_table = NULL;
	int err;

	hash_table = init_hashtable();
	ck_assert_ptr_nonnull(hash_table);

	err = prepare_sql(db, hash_table);
	ck_assert(err == CODE_SUCCESS);
}
END_TEST

START_TEST(test_begin_transaction__FAIL__no_prepare)
{
	int err;

	err = begin_transaction(db, ht);
	ck_assert(err == CODE_FAILED);
}
END_TEST

START_TEST(test_begin_transaction__SUCCESS)
{
	int err;

	err = prepare_sql(db, ht);
	ck_assert(err == CODE_SUCCESS);

	err = begin_transaction(db, ht);
	ck_assert(err == CODE_SUCCESS);
}
END_TEST

START_TEST(test_rollback_transaction__FAIL__no_prepare)
{
	int err;

	err = rollback_transaction(db, ht);
	ck_assert(err == CODE_FAILED);
}
END_TEST

START_TEST(test_rollback_transaction__FAIL__no_transaction)
{
	int err;

	err = prepare_sql(db, ht);
	ck_assert(err == CODE_SUCCESS);

	err = rollback_transaction(db, ht);
	ck_assert(err == CODE_FAILED);
}
END_TEST

START_TEST(test_rollback_transaction__SUCCESS)
{
	int err;

	err = prepare_sql(db, ht);
	ck_assert(err == CODE_SUCCESS);

	err = begin_transaction(db, ht);
	ck_assert(err == CODE_SUCCESS);

	err = rollback_transaction(db, ht);
	ck_assert(err == CODE_SUCCESS);
}
END_TEST

START_TEST(test_commit_transaction__FAIL__no_prepare)
{
	int err;

	err = commit_transaction(db, ht);
	ck_assert(err == CODE_FAILED);
}
END_TEST

START_TEST(test_commit_transaction__FAIL__no_transaction)
{
	int err;

	err = prepare_sql(db, ht);
	ck_assert(err == CODE_SUCCESS);

	err = commit_transaction(db, ht);
	ck_assert(err == CODE_RETRY);
}
END_TEST

START_TEST(test_commit_transaction__SUCCESS)
{
	int err;

	err = prepare_sql(db, ht);
	ck_assert(err == CODE_SUCCESS);

	err = begin_transaction(db, ht);
	ck_assert(err == CODE_SUCCESS);

	err = commit_transaction(db, ht);
	ck_assert(err == CODE_SUCCESS);
}
END_TEST

#define TP 5299989644498
#define PP 233306918540337

#define INITIALIZE_EVENT(dt)                                                   \
	struct probe_event_header eh = { .event_time = 12345678,               \
					 .tgid_pid = TP,                       \
					 .comm = "test",                       \
					 .syscall_nr = SYS_EXECVE,             \
					 .data_type = dt }

int validate_callback__insert_event(void *eh_in, int n, char **vals,
				    char **names)
{
	long l;
	struct probe_event_header *eh = (struct probe_event_header *)eh_in;

	for (int i = 0; i < n; i++) {
		if (strcmp(names[i], EVENT_TIME) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate__insert_event: could not convert event_time:%s to long\n",
					vals[i]);
				return 1;
			}
			if (l != eh->event_time) {
				fprintf(stderr,
					"validate__insert_event: vals[i] (%ld) != eh->event_time (%ld)\n",
					l, eh->event_time);
				return 1;
			}
		} else if (strcmp(names[i], TGID) == 0) {
			// TODO: fix this test for TGID & PID
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate__insert_event: could not convert tgid_pid (%s) to long\n",
					vals[i]);
				return 1;
			}
			if (l != eh->tgid_pid) {
				fprintf(stderr,
					"validate__insert_event: vals[i] (%ld) != eh->tgid_pid (%ld)\n",
					l, eh->tgid_pid);
				return 1;
			}
		} else if (strcmp(names[i], SYSCALL) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate__insert_event: could not convert syscall (%s) to long\n",
					vals[i]);
				return 1;
			}
			if (l != eh->syscall_nr) {
				fprintf(stderr,
					"validate__insert_event: vals[i] (%ld) != eh->syscall (%ld)\n",
					l, eh->syscall_nr);
				return 1;
			}
		} else if (strcmp(names[i], COMM) == 0) {
			if (strcmp(vals[i], eh->comm) != 0) {
				fprintf(stderr,
					"validate__insert_event: vals[i] (%s) != eh->comm (%s)\n",
					vals[i], eh->comm);
				return 1;
			}
		}
	}

	return 0;
}

void validate__insert_event(struct probe_event_header *eh, int event_id)
{
	int err;

	char sql[256];
	sprintf(sql, "SELECT * FROM events WHERE event_id = %d", event_id);

	err = sqlite3_exec(db, sql, validate_callback__insert_event, eh, NULL);
	ck_assert(err != SQLITE_ABORT);
}

START_TEST(test_insert_event__SUCCESS)
{
	int err;

	INITIALIZE_EVENT(1);
	err = insert_event(db, ht, &eh);
	ck_assert(err != CODE_RETRY);
	ck_assert(err > 0);

	validate__insert_event(&eh, err);
}
END_TEST

struct file_info_data {
	struct file_info *f;
	char *filename;
};

int validate_callback__insert_file_info(void *d_in, int n, char **vals,
					char **names)
{
	long l;
	struct file_info_data *d = (struct file_info_data *)d_in;
	struct file_info *f = d->f;
	char *filename = d->filename;

	for (int i = 0; i < n; i++) {
		if (strcmp(names[i], S_MAGIC) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_file_info: could not convert s_magic:%s to long\n",
					vals[i]);
				return 1;
			}
			if (l != f->s_magic) {
				fprintf(stderr,
					"validate_callback__insert_file_info: vals[i] (%ld) != f->s_magic (%ld)\n",
					l, f->s_magic);
				return 1;
			}
		} else if (strcmp(names[i], INODE_NUMBER) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_file_info: could not convert i_ino (%s) to long\n",
					vals[i]);
				return 1;
			}
			if (l != f->i_ino) {
				fprintf(stderr,
					"validate_callback__insert_file_info: vals[i] (%ld) != f->i_ino (%ld)\n",
					l, f->i_ino);
				return 1;
			}
		} else if (strcmp(names[i], FILENAME) == 0) {
			if (vals[i] == NULL) {
				if (filename != NULL)
					return 1;
			} else if (filename == NULL) {
				fprintf(stderr,
					"validate_callback__insert_file_info: filename passed to validate function is NULL\n");
				return 1;
			} else if (strcmp(vals[i], filename) != 0) {
				fprintf(stderr,
					"validate_callback__insert_file_info: vals[i] (%s) != filename (%s)\n",
					vals[i], filename);
				return 1;
			}
		}
	}

	return 0;
}

void validate__insert_file_info(struct file_info_data *d, int file_id)
{
	int err;

	char sql[256];
	sprintf(sql, "SELECT * FROM file_info WHERE file_id = %d", file_id);

	err = sqlite3_exec(db, sql, validate_callback__insert_file_info, d,
			   NULL);
	ck_assert(err != SQLITE_ABORT);
}

START_TEST(test_insert_file_info__SUCCESS__no_filename)
{
	int err;

	struct file_info f = { .file_offset =
				       LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE),
			       .path_len = 0,
			       .i_ino = 666,
			       .s_magic = 1 };

	err = insert_file_info(db, ht, NULL, &f);
	ck_assert(err != CODE_RETRY);
	ck_assert(err > 0);

	struct file_info_data d = { .f = &f, .filename = NULL };
	validate__insert_file_info(&d, err);
}
END_TEST

START_TEST(test_insert_file_info__SUCCESS__filename)
{
	int err;

	char *string;
	struct file_info f = {
		.file_offset = 0, .path_len = 3, .i_ino = 666, .s_magic = 1
	};

	string = calloc(PER_CPU_STR_BUFFSIZE, sizeof(char));
	ck_assert_ptr_nonnull(string);

	memcpy(string, "llvm\0lib\0usr\0", 13);

	err = insert_file_info(db, ht, string, &f);
	ck_assert(err != CODE_RETRY);
	ck_assert(err > 0);

	struct file_info_data d = { .f = &f, .filename = "/usr/lib/llvm" };
	validate__insert_file_info(&d, err);

	free(string);
}
END_TEST

//START_TEST(test_insert_mmap_info__FAIL__no_event) {
//	int err;
//
//	INITIALIZE_EVENT(1);
//	struct proc_mmap pm = { .eh = eh, .vm_base = 0xffffffff, .vm_flags = 1, .vm_prot = 2, .vm_len = 0x1000 };
//
//	err = commit_transaction(db, ht);
//	err = insert_mmap_info(db, ht, &pm, 0, -1);
//	ck_assert(err == CODE_RETRY);
//}
//END_TEST

int validate_callback__insert_mmap_info(void *pm_in, int n, char **vals,
					char **names)
{
	long l;
	struct proc_mmap *pm = (struct proc_mmap *)pm_in;

	for (int i = 0; i < n; i++) {
		if (strcmp(names[i], VM_BASE) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_mmap_info: could not convert vm_base:%s to long\n",
					vals[i]);
				return 1;
			}
			if (l != pm->vm_base) {
				fprintf(stderr,
					"validate_callback__insert_mmap_info: vals[i] (%ld) != pm->vm_base (%ld)\n",
					l, pm->vm_base);
				return 1;
			}
		} else if (strcmp(names[i], VM_FLAGS) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"v: could not convert vm_flags (%s) to long\n",
					vals[i]);
				return 1;
			}
			if (l != pm->vm_flags) {
				fprintf(stderr,
					"validate__insert_mmap_info: vals[i] (%ld) != pm->vm_flags (%ld)\n",
					l, pm->vm_flags);
				return 1;
			}
		} else if (strcmp(names[i], VM_PROT) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"v: could not convert vm_prot (%s) to long\n",
					vals[i]);
				return 1;
			}
			if (l != pm->vm_prot) {
				fprintf(stderr,
					"validate__insert_mmap_info: vals[i] (%ld) != pm->vm_prot (%ld)\n",
					l, pm->vm_prot);
				return 1;
			}
		} else if (strcmp(names[i], VM_LEN) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"v: could not convert vm_len (%s) to long\n",
					vals[i]);
				return 1;
			}
			if (l != pm->vm_prot) {
				fprintf(stderr,
					"validate__insert_mmap_info: vals[i] (%ld) != pm->vm_len (%ld)\n",
					l, pm->vm_len);
				return 1;
			}
		}
	}

	return 0;
}

void validate__insert_mmap_info(struct proc_mmap *pm, int event_id)
{
	int err;
	char sql[256];
	sprintf(sql, "SELECT * FROM proc_mmap WHERE event_id = %d\n", event_id);

	err = sqlite3_exec(db, sql, validate_callback__insert_mmap_info, pm,
			   NULL);
	ck_assert(err != SQLITE_ABORT);
}

START_TEST(test_insert_mmap_info__SUCCESS)
{
	int err, event_id;

	INITIALIZE_EVENT(1);
	struct proc_mmap pm = { .eh = eh,
				.vm_base = 0xffffffff,
				.vm_flags = 1,
				.vm_prot = 2,
				.vm_len = 0x1000 };

	err = insert_event(db, ht, &eh);
	ck_assert(err != CODE_RETRY);
	ck_assert(err > 0);
	event_id = err;

	err = insert_mmap_info(db, ht, &pm, err, -1);
	ck_assert(err == CODE_SUCCESS);

	validate__insert_mmap_info(&pm, err);
}
END_TEST

static char *build_args_str(char *args_data, uint32_t argv_off, uint32_t nargv)
{
	uint32_t cnt, indx;
	size_t arg_sz;
	char *args = NULL;
	char *dest = NULL;
	char *str = NULL;

	for (indx = argv_off, cnt = 0; cnt < nargv; indx++) {
		if (indx >= PER_CPU_STR_BUFFSIZE) {
			ASSERT(indx < PER_CPU_STR_BUFFSIZE,
			       "build_args_str: indx >= PER_CPU_STR_BUFFSIZE");
			return NULL;
		}
		if (args_data[indx] == 0)
			cnt++;
	}

	arg_sz = indx - argv_off;
	args = calloc(arg_sz, sizeof(char));
	if (args != NULL) {
		dest = args;
		str = &(args_data[argv_off]);
		for (uint32_t i = 0; i < nargv; ++i) {
			args = strcat(args, str);
			dest = strchr(args, '\0');
			*dest = ',';
			str = strchr(str, '\0');
			str++;
		}

		return args;
	} else {
		return NULL;
	}
}

int validate_callback__insert_proc_info(void *msg_in, int n, char **vals,
					char **names)
{
	long l;
	struct message_state *ms = (struct message_state *)msg_in;
	struct process_info *pinfo = (struct process_info *)ms->primary_data;
	char *str = (char *)MESSAGE_STRING(ms);
	char *args = NULL;

	for (int i = 0; i < n; i++) {
		// TODO: Fix the test as ppid is split in two columns
		if (strcmp(names[i], PPID) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: could not convert ppid:%s to long\n",
					vals[i]);
				return 1;
			}

			if (l != pinfo->ppid) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: vals[i] (%ld) != pinfo->ppid (%ld)\n",
					l, pinfo->ppid);
				return 1;
			}
		} else if (strcmp(names[i], ARGS) == 0) {
			args = build_args_str(str, pinfo->args.argv_offset,
					      pinfo->args.nargv);
			if (args != NULL) {
				if ((vals[i] != NULL) &&
				    (strcmp(vals[i], args) != 0)) {
					fprintf(stderr,
						"validate_callback__insert_proc_info: vals[i] (%s) != args (%s)\n",
						vals[i], args);
					return 1;
				}
			} else {
				if (vals[i] != NULL) {
					fprintf(stderr,
						"validate_callback__insert_proc_info: vals[i] (%s) != args (%s)\n",
						vals[i], args);
					return 1;
				}
			}
		} else if (strcmp(names[i], INTERPRETER) == 0) {
			char *interp = &(str[pinfo->interp_str_offset]);
			if (strcmp(vals[i], interp) != 0) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: vals[i] (%s) != interpreter (%s)\n",
					vals[i], interp);
				return 1;
			}
		} else if (strcmp(names[i], UID) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: could not convert uid:%s to long\n",
					vals[i]);
				return 1;
			}

			if (l != pinfo->credentials.uid) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: vals[i] (%ld) != pinfo->uid (%ld)\n",
					l, pinfo->credentials.uid);
				return 1;
			}
		} else if (strcmp(names[i], GID) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: could not convert gid:%s to long\n",
					vals[i]);
				return 1;
			}

			if (l != pinfo->credentials.gid) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: vals[i] (%ld) != pinfo->gid (%ld)\n",
					l, pinfo->credentials.gid);
				return 1;
			}
		} else if (strcmp(names[i], EUID) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: could not convert ppid:%s to long\n",
					vals[i]);
				return 1;
			}

			if (l != pinfo->credentials.euid) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: vals[i] (%ld) != pinfo->euid (%ld)\n",
					l, pinfo->credentials.euid);
				return 1;
			}
		} else if (strcmp(names[i], EGID) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: could not convert ppid:%s to long\n",
					vals[i]);
				return 1;
			}

			if (l != pinfo->credentials.egid) {
				fprintf(stderr,
					"validate_callback__insert_proc_info: vals[i] (%ld) != pinfo->egid (%ld)\n",
					l, pinfo->credentials.egid);
				return 1;
			}
		}
	}

	return 0;
}

void validate__insert_proc_info(struct message_state *pinfo, int event_id)
{
	int err;
	char sql[256];
	sprintf(sql, "SELECT * FROM process_info WHERE event_id = %d",
		event_id);

	err = sqlite3_exec(db, sql, validate_callback__insert_proc_info, pinfo,
			   NULL);
	ck_assert(err != SQLITE_ABORT);

	return;
}

START_TEST(test_insert_proc_info__SUCCESS)
{
	int err, event_id;

	INITIALIZE_EVENT(1);
	struct process_info pinfo = { .eh = eh,
				      .ppid = PP,
				      .args = { .argv_offset = 11, .nargv = 3 },
				      .interp_str_offset = 0,
				      .io = { 1, 2, 3 },
				      .credentials = { 1000, 1000, 1000,
						       1000 } };
	struct message_state ms = {
		.primary_data = &pinfo,
		.str_data = { .string = "/bin/bash\0-arg1\0-arg2\0-arg3\0",
			      .str_size = 28 }
	};

	err = insert_event(db, ht, &eh);
	ck_assert(err != CODE_RETRY);
	ck_assert(err > 0);
	event_id = err;

	err = insert_proc_info(db, ht, &ms, event_id, 1);
	ck_assert(err == CODE_SUCCESS);

	validate__insert_proc_info(&ms, event_id);
}
END_TEST

START_TEST(test_insert_event__SUCCESS__no_args)
{
	int err, event_id;

	INITIALIZE_EVENT(1);
	struct process_info pinfo = {
		.eh = eh,
		.ppid = PP,
		.args = { .argv_offset = 4095, .nargv = 0 },
		.interp_str_offset = 0,
		.io = { 1, 2, 3 },
		.credentials = { 1000, 1000, 1000, 1000 }
	};
	struct message_state ms = { .primary_data = &pinfo,
				    .str_data = { .string = "/bin/bash\0",
						  .str_size = 10 } };

	err = insert_event(db, ht, &eh);
	ck_assert(err != CODE_RETRY);
	ck_assert(err > 0);
	event_id = err;

	err = insert_proc_info(db, ht, &ms, event_id, 1);
	ck_assert(err == CODE_SUCCESS);

	validate__insert_proc_info(&ms, event_id);
}

START_TEST(test_insert_proc_info__SUCCESS__no_interpreter)
{
	int err, event_id;

	INITIALIZE_EVENT(1);
	struct process_info pinfo = { .eh = eh,
				      .ppid = PP,
				      .args = { .argv_offset = 0, .nargv = 3 },
				      .interp_str_offset = 4095,
				      .io = { 1, 2, 3 },
				      .credentials = { 1000, 1000, 1000,
						       1000 } };
	struct message_state ms = { .primary_data = &pinfo,
				    .str_data = {
					    .string = "-arg1\0-arg2\0-arg3\0",
					    .str_size = 28 } };

	err = insert_event(db, ht, &eh);
	ck_assert(err != CODE_RETRY);
	ck_assert(err > 0);
	event_id = err;

	err = insert_proc_info(db, ht, &ms, event_id, 1);
	ck_assert(err == CODE_SUCCESS);

	validate__insert_proc_info(&ms, event_id);
}
END_TEST

static int family_identifier(char *fam)
{
	if (strcmp(fam, "ipv4") == 0) {
		return AF_INET;
	}
	if (strcmp(fam, "ipv6") == 0) {
		return AF_INET6;
	}

	return -1;
}

int validate_callback__insert_socket_create_info(void *ms_in, int n,
						 char **vals, char **names)
{
	long l;
	struct message_state *ms = (struct message_state *)ms_in;
	struct socket_create *sinfo = (struct socket_create *)ms->primary_data;

	for (int i = 0; i < n; ++i) {
		if (strcmp(names[i], INODE_NUMBER) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_socket_create_info: could not convert inode_numer:%s to long\n",
					vals[i]);
				return 1;
			}

			if (l != sinfo->i_ino) {
				fprintf(stderr,
					"validate_callback__insert_socket_create_info: vals[i] (%ld) != sinfo->i_ino (%ld)\n",
					l, sinfo->i_ino);
				return 1;
			}
		} else if (strcmp(names[i], FAMILY) == 0) {
			l = family_identifier(vals[i]);
			if (l == -1) {
				fprintf(stderr,
					"validate_callback__insert_socket_create_info: unknown familty type (%s)\n",
					vals[i]);
				return 1;
			}
			if (l != sinfo->family) {
				fprintf(stderr,
					"validate_callback__insert_socket_create_info: vals[i] (%ld) != sinfo->family (%ld)\n",
					l, sinfo->family);
				return 1;
			}
		} else if (strcmp(names[i], TYPE) == 0) {
			l = strtol(vals[i], NULL, 10);
			if (l == 0) {
				fprintf(stderr,
					"validate_callback__insert_socket_create_info: could not convert type:%s to long\n",
					vals[i]);
				return 1;
			}

			if (l != sinfo->type) {
				fprintf(stderr,
					"validate_callback__insert_socket_create_info: vals[i] (%ld) != sinfo->type (%ld)\n",
					l, sinfo->type);
				return 1;
			}
		}
	}

	return 0;
}

void validate__insert_socket_create_info(struct message_state *ms, int event_id)
{
	int err;

	char sql[256];
	sprintf(sql, "SELECT * FROM socket_create_info WHERE event_id = %d",
		event_id);

	err = sqlite3_exec(db, sql,
			   validate_callback__insert_socket_create_info, ms,
			   NULL);
	ck_assert(err != SQLITE_ABORT);
}

START_TEST(test_insert_socket_create_info__SUCCESS)
{
	int err, event_id;

	INITIALIZE_EVENT(1);
	struct socket_create sinfo = {
		.eh = eh, .i_ino = 1, .family = AF_INET, .type = SOCK_STREAM
	};
	struct message_state ms = {
		.primary_data = &sinfo,
	};

	err = insert_event(db, ht, &eh);
	ck_assert(err != CODE_RETRY);
	ck_assert(err > 0);
	event_id = err;

	err = insert_socket_create_info(db, ht, &ms, event_id);
	ck_assert(err == CODE_SUCCESS);

	validate__insert_socket_create_info(&ms, event_id);
}
END_TEST

START_TEST(test_insert_socket_create_info__FAIL__invalid_family)
{
	int err, event_id;

	INITIALIZE_EVENT(1);
	struct socket_create sinfo = {
		.eh = eh, .i_ino = 1, .family = ~AF_INET, .type = SOCK_STREAM
	};
	struct message_state ms = {
		.primary_data = &sinfo,
	};

	err = insert_event(db, ht, &eh);
	ck_assert(err != CODE_RETRY);
	ck_assert(err > 0);
	event_id = err;

	err = insert_socket_create_info(db, ht, &ms, event_id);
	ck_assert(err == CODE_FAILED);
}
END_TEST

Suite *database_suite(void)
{
	Suite *s;
	TCase *tc_create_conn, *tc_prepare_sql, *tc_begin_transaction,
		*tc_rollback_transaction;
	TCase *tc_commit_transaction, *tc_insert_event, *tc_insert_file_info,
		*tc_insert_mmap_info;
	TCase *tc_insert_proc_info, *tc_insert_socket_create_info,
		*tc_insert_tcp_conn_info;

	s = suite_create("Database");

	/* Create Connection */
	tc_create_conn = tcase_create("Create Database");
	tcase_add_test(tc_create_conn, test_create_connection);

	/* Prepare SQL */
	tc_prepare_sql = tcase_create("Prepare SQL");
	tcase_add_checked_fixture(tc_prepare_sql, create_database,
				  delete_database);
	tcase_add_test(tc_prepare_sql, test_prepare_sql);

	/* Begin transaction */
	tc_begin_transaction = tcase_create("Begin transaction");
	tcase_add_checked_fixture(tc_begin_transaction, create_database,
				  delete_database);
	tcase_add_checked_fixture(tc_begin_transaction, create_hashtable,
				  delete_hashtable);
	tcase_add_test(tc_begin_transaction,
		       test_begin_transaction__FAIL__no_prepare);
	tcase_add_test(tc_begin_transaction, test_begin_transaction__SUCCESS);

	/* Rollback transaction */
	tc_rollback_transaction = tcase_create("Rollback transaction");
	tcase_add_checked_fixture(tc_rollback_transaction, create_database,
				  delete_database);
	tcase_add_checked_fixture(tc_rollback_transaction, create_hashtable,
				  delete_hashtable);
	tcase_add_test(tc_rollback_transaction,
		       test_rollback_transaction__FAIL__no_prepare);
	tcase_add_test(tc_rollback_transaction,
		       test_rollback_transaction__FAIL__no_transaction);
	tcase_add_test(tc_rollback_transaction,
		       test_rollback_transaction__SUCCESS);

	/* Commit transaction */
	tc_commit_transaction = tcase_create("Commit transaction");
	tcase_add_checked_fixture(tc_commit_transaction, create_database,
				  delete_database);
	tcase_add_checked_fixture(tc_commit_transaction, create_hashtable,
				  delete_hashtable);
	tcase_add_test(tc_commit_transaction,
		       test_commit_transaction__FAIL__no_prepare);
	tcase_add_test(tc_commit_transaction,
		       test_commit_transaction__FAIL__no_transaction);
	tcase_add_test(tc_commit_transaction, test_commit_transaction__SUCCESS);

	/* Insert event */
	tc_insert_event = tcase_create("Insert event");
	tcase_add_checked_fixture(tc_insert_event, create_database,
				  delete_database);
	tcase_add_checked_fixture(tc_insert_event, create_hashtable,
				  delete_hashtable);
	tcase_add_checked_fixture(tc_insert_event, pre__insert, post__insert);
	tcase_add_test(tc_insert_event, test_insert_event__SUCCESS);

	/* Insert file info */
	tc_insert_file_info = tcase_create("Insert file info");
	tcase_add_checked_fixture(tc_insert_file_info, create_database,
				  delete_database);
	tcase_add_checked_fixture(tc_insert_file_info, create_hashtable,
				  delete_hashtable);
	tcase_add_checked_fixture(tc_insert_file_info, pre__insert,
				  post__insert);
	tcase_add_test(tc_insert_file_info,
		       test_insert_file_info__SUCCESS__no_filename);
	tcase_add_test(tc_insert_file_info,
		       test_insert_file_info__SUCCESS__filename);

	/* Insert mmap */
	tc_insert_mmap_info = tcase_create("Insert Mmap");
	tcase_add_checked_fixture(tc_insert_mmap_info, create_database,
				  delete_database);
	tcase_add_checked_fixture(tc_insert_mmap_info, create_hashtable,
				  delete_hashtable);
	tcase_add_checked_fixture(tc_insert_mmap_info, pre__insert,
				  post__insert);
	//	tcase_add_test(tc_insert_mmap_info, test_insert_mmap_info__FAIL__no_event);
	tcase_add_test(tc_insert_mmap_info, test_insert_mmap_info__SUCCESS);

	/* Insert process info */
	tc_insert_proc_info = tcase_create("Insert process info");
	tcase_add_checked_fixture(tc_insert_proc_info, create_database,
				  delete_database);
	tcase_add_checked_fixture(tc_insert_proc_info, create_hashtable,
				  delete_hashtable);
	tcase_add_checked_fixture(tc_insert_proc_info, pre__insert,
				  post__insert);
	tcase_add_test(tc_insert_proc_info, test_insert_proc_info__SUCCESS);
	tcase_add_test(tc_insert_proc_info,
		       test_insert_event__SUCCESS__no_args);
	tcase_add_test(tc_insert_proc_info,
		       test_insert_proc_info__SUCCESS__no_interpreter);

	/* Insert socket create info */
	tc_insert_socket_create_info =
		tcase_create("Insert socket create info");
	tcase_add_checked_fixture(tc_insert_socket_create_info, create_database,
				  delete_database);
	tcase_add_checked_fixture(tc_insert_socket_create_info,
				  create_hashtable, delete_hashtable);
	tcase_add_checked_fixture(tc_insert_socket_create_info, pre__insert,
				  post__insert);
	tcase_add_test(tc_insert_socket_create_info,
		       test_insert_socket_create_info__SUCCESS);
	tcase_add_test(tc_insert_socket_create_info,
		       test_insert_socket_create_info__FAIL__invalid_family);

	suite_add_tcase(s, tc_create_conn);
	suite_add_tcase(s, tc_prepare_sql);
	suite_add_tcase(s, tc_begin_transaction);
	suite_add_tcase(s, tc_rollback_transaction);
	suite_add_tcase(s, tc_commit_transaction);
	suite_add_tcase(s, tc_insert_event);
	suite_add_tcase(s, tc_insert_file_info);
	suite_add_tcase(s, tc_insert_mmap_info);
	suite_add_tcase(s, tc_insert_proc_info);
	suite_add_tcase(s, tc_insert_socket_create_info);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s1;
	SRunner *sr;

	s1 = database_suite();
	sr = srunner_create(s1);

	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
