/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * The file contains all the code for initializing the database, preparing sql
 * statements, and inserting all the different kinds of events.
 */

#include "stmts.h"
#include "notifier.h"
#include "enum_str.h"
#include "helper_defs.h"
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdio.h>
#include <err.h>
#include <events.h>
#include <hash.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <helpers.h>
#include <sys/socket.h> // AF_INET, AF_INET6
#include <arpa/inet.h>
#include "database.h"

static void delete_db_file(char *dbname)
{
	int err;

	err = remove(dbname);
	if (err)
		fprintf(stderr, "Could not delete invalid db file: %d\n",
			errno);
}

#define EXEC_PRAGMA(pragma, db)                                                   \
	err = sqlite3_exec(db, pragma, NULL, NULL, &err_msg);                     \
	if (err != SQLITE_OK) {                                                   \
		fprintf(stderr,                                                   \
			STRINGIFY(                                                \
				pragma) ": Could not run pragma statement: %s\n", \
			sqlite3_errmsg(db));                                      \
		err = CODE_FAILED;                                                \
		goto out;                                                         \
	}

#define INSERT_COM_STMT(comm)                                                  \
	"INSERT INTO disallowed(" COMM ") VALUES('" comm "');"

typedef struct disallowed {
	char *proc_name;
} dis_t;

const dis_t DISALLOWED[] = { { INSERT_COM_STMT("nginx") },
			     { INSERT_COM_STMT("httpd") },
			     { INSERT_COM_STMT("httpd-foregroun") },
			     { INSERT_COM_STMT("lighttpd") },
			     { INSERT_COM_STMT("apache") },
			     { INSERT_COM_STMT("apache2") },
			     { INSERT_COM_STMT("java") } };

#define NUM_DISALLOWED (sizeof(DISALLOWED) / sizeof(DISALLOWED[0]))

static void populate_disallowed(sqlite3 *db)
{
	int err;
	char *err_msg;

	for (unsigned int i = 0; i < NUM_DISALLOWED; i++) {
		err = sqlite3_exec(db, DISALLOWED[i].proc_name, NULL, NULL,
				   &err_msg);
		if (err != SQLITE_OK) {
			fprintf(stderr,
				"SQL error during insert on disallowed '%s': %s\n",
				DISALLOWED[i].proc_name, err_msg);
		}
	}
}

int initialize_database(char *dbname)
{
	struct stat sb;
	sqlite3 *db;
	int err;
	char *err_msg;

	db = NULL;
	if (!dbname) {
		fprintf(stderr, "Invalid dbname. dbname cannot be NULL\n");
		return CODE_FAILED;
	}

	// return success if db exists.
	if (!stat(dbname, &sb)) {
		return CODE_SUCCESS;
	}

	err = sqlite3_open(dbname, &db);
	if (err) {
		fprintf(stderr, "Can't open database: %s\n",
			sqlite3_errmsg(db));
		sqlite3_close(db);
		err = CODE_FAILED;
		goto out;
	}

	for (unsigned int i = 0; i < N_CREATE_STMTS; ++i) {
		err_msg = NULL;
		err = sqlite3_exec(db, CREATE_STMTS[i], NULL, NULL, &err_msg);
		if (err != SQLITE_OK) {
			fprintf(stderr,
				"SQL error during db initialization for '%s': %s\n",
				CREATE_STMTS[i], err_msg);
			sqlite3_close(db);

			delete_db_file(dbname);
			err = CODE_FAILED;
			goto out;
		}
	}

	EXEC_PRAGMA(JOURNAL_MODE, db); // WAL mode is persistent
	EXEC_PRAGMA(SYNCHRONOUS, db);
	EXEC_PRAGMA(TEMP_STORE, db);

	populate_disallowed(db);

	err = CODE_SUCCESS;
out:
	if (db != NULL)
		sqlite3_close(db);

	return err;
}

int create_connection(char *dbname, sqlite3 **database, int inmem)
{
	int err;
	struct stat sb;
	char *err_msg;
	int flags;

	if (!dbname) {
		fprintf(stderr, "Invalid dbname. dbname cannot be NULL\n");
		return EINVAL;
	}

	flags = SQLITE_OPEN_READWRITE;
	if (inmem) {
		flags |= SQLITE_OPEN_MEMORY;
	} else {
		if (stat(dbname, &sb)) {
			fprintf(stderr,
				"Invalid dbname. File does not exist\n");
			return CODE_FAILED;
		}
	}

	//	err = sqlite3_open(dbname, database);
	err = sqlite3_open_v2(dbname, database, flags, NULL);
	if (err) {
		fprintf(stderr, "Can't open database: %s\n",
			sqlite3_errmsg(*database));
		sqlite3_close(*database);
		return CODE_FAILED;
	}

	err = sqlite3_busy_timeout(*database, TIMEOUT_MS);

	// SQLite optimizations runtime
	EXEC_PRAGMA(MMAP_SIZE, *database);

	err = CODE_SUCCESS;
out:
	return err;
}

void close_database(sqlite3 *database)
{
	sqlite3_db_cacheflush(database);
	sqlite3_close(database);
}

int prepare_sql(sqlite3 *db, hashtable_t *hash_table)
{
	sqlite3_stmt *ppStmt;
	int err;

	// initialize user defined functions
	err = init_notifier(db, hash_table);

	// Save prepared insert statements in hashmap
	for (unsigned int i = 0; i < NUM_OF_STMTS; i++) {
		err = sqlite3_prepare_v2(db, SQL_STMTS[i].sql,
					 (int)SQL_STMTS[i].sql_len, &ppStmt,
					 NULL);
		if (err != SQLITE_OK) {
			fprintf(stderr,
				"[err:%d:%s] Failed to prepare sql: %s.\n", err,
				sqlite3_errmsg(db), SQL_STMTS[i].sql);
			return CODE_FAILED;
		}

		err = hash_put(hash_table, SQL_STMTS[i].sql, ppStmt,
			       SQL_STMTS[i].sql_len);
		if (err == CODE_FAILED) {
			fprintf(stderr,
				"Failed to place prepared statement in hashmap.\n");
			return CODE_FAILED;
		}
	}

	return err;
}

int begin_transaction(sqlite3 *db, hashtable_t *ht)
{
	sqlite3_stmt *ppStmt;
	int err;

	ppStmt = hash_get(ht, BEGIN_STMT, sizeof(BEGIN_STMT));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"begin_transaction: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	err = sqlite3_step(ppStmt);
	if (err != SQLITE_DONE)
		return CODE_RETRY;

	return CODE_SUCCESS;
}

int rollback_transaction(sqlite3 *db, hashtable_t *ht)
{
	sqlite3_stmt *ppStmt;
	int err;

	ppStmt = hash_get(ht, ROLLBACK_STMT, sizeof(ROLLBACK_STMT));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"rollback_transaction: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	err = sqlite3_step(ppStmt);
	if (err != SQLITE_DONE) {
		fprintf(stderr,
			"rollback_transaction: err != SQLITE_DONE: %s\n",
			sqlite3_errmsg(db));
		return CODE_FAILED;
	}

	return CODE_SUCCESS;
}

int commit_transaction(sqlite3 *db, hashtable_t *ht)
{
	sqlite3_stmt *ppStmt;
	int err;

	ppStmt = hash_get(ht, COMMIT_STMT, sizeof(COMMIT_STMT));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"commit_transaction: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	err = sqlite3_step(ppStmt);
	if (err != SQLITE_DONE)
		return CODE_RETRY;

	return CODE_SUCCESS;
}

int insert_event(sqlite3 *db, hashtable_t *ht, struct probe_event_header *eh)
{
	sqlite3_stmt *ppStmt;
	int err;
	int event_id;
	u64_t tgid;
	u64_t pid;

	ppStmt = hash_get(ht, INSERT_EVENT, sizeof(INSERT_EVENT));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_event: Failed to acquire prepared statement for insert event from hashmap.\n");
		return CODE_FAILED;
	}

	tgid = (eh->tgid_pid >> 32) & 0xFFFFFFFF;
	pid = eh->tgid_pid & 0xFFFFFFFF;

	SQLITE3_BIND_INT("insert_event", int64, EVENT_TIME, eh->event_time);
	SQLITE3_BIND_INT("insert_event", int64, TGID, tgid);
	SQLITE3_BIND_INT("insert_event", int64, PID, pid);
	SQLITE3_BIND_INT("insert_event", int, SYSCALL, eh->syscall_nr);
	SQLITE3_BIND_STR("insert_event", text, COMM, eh->comm);

	err = sqlite3_step(ppStmt);
	event_id =
		err == SQLITE_ROW ? sqlite3_column_int(ppStmt, 0) : CODE_RETRY;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return event_id;
}

static int select_file_info_row(sqlite3 *db, hashtable_t *ht,
				unsigned long inode_number,
				unsigned long s_magic)
{
	int file_id, err;
	sqlite3_stmt *ppStmt;

	ppStmt = hash_get(ht, SELECT_FILE_ID, sizeof(SELECT_FILE_ID));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"select_file_info_row: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	SQLITE3_BIND_INT("select_file_info", int64, INODE_NUMBER, inode_number);
	SQLITE3_BIND_INT("select_file_info", int64, S_MAGIC, s_magic);

	err = sqlite3_step(ppStmt);
	//ASSERT(err == SQLITE_ROW, "select_file_info_row: err != SQLITE_ROW");

	if (err == SQLITE_ROW)
		file_id = sqlite3_column_int(ppStmt, 0);
	else
		file_id = CODE_FAILED;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return file_id;
}

int insert_file_info(sqlite3 *db, hashtable_t *ht, char *string_data,
		     struct file_info *f)
{
	int file_id, err;
	sqlite3_stmt *ppStmt;
	char *filename = NULL;

	if (f->i_ino == 0)
		return CODE_FAILED;

	// If file information already exists in database return its ID.
	file_id = select_file_info_row(db, ht, f->i_ino, f->s_magic);
	if (file_id != CODE_FAILED)
		return file_id;

	// If file not present in database, insert.
	ppStmt = (sqlite3_stmt *)hash_get(ht, INSERT_FILE_INFO,
					  sizeof(INSERT_FILE_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_file_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	SQLITE3_BIND_INT("insert_file_info", int64, INODE_NUMBER, f->i_ino);
	SQLITE3_BIND_INT("insert_file_info", int64, S_MAGIC, f->s_magic);

	if (f->file_offset < LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE)) {
		filename = build_filename_from_event(
			&string_data[f->file_offset], f->path_len);
		if (filename != NULL) {
			SQLITE3_BIND_STR("insert_file_info", text, FILENAME,
					 filename);
		}
	}

	err = sqlite3_step(ppStmt);
	if (err == SQLITE_ROW)
		file_id = sqlite3_column_int(ppStmt, 0);
	else
		file_id = CODE_RETRY;
	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	if (filename != NULL)
		free(filename);

	return file_id;
}

int insert_mmap_info(sqlite3 *db, hashtable_t *ht, struct proc_mmap *pm,
		     int event_id, int file_id)
{
	sqlite3_stmt *ppStmt;
	int err;

	ppStmt = hash_get(ht, INSERT_PROC_MMAP, sizeof(INSERT_PROC_MMAP));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_mmap_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	SQLITE3_BIND_INT("insert_mmap_info", int64, VM_BASE, pm->vm_base);
	SQLITE3_BIND_INT("insert_mmap_info", int64, VM_FLAGS, pm->vm_flags);
	SQLITE3_BIND_INT("insert_mmap_info", int64, VM_PROT, pm->vm_prot);
	SQLITE3_BIND_INT("insert_mmap_info", int64, VM_LEN, pm->vm_len);
	SQLITE3_BIND_INT("insert_mmap_info", int, EVENT_ID, event_id);

	if (file_id < 0)
		sqlite3_bind_null(ppStmt,
				  sqlite3_bind_parameter_index(
					  ppStmt, PARAM_HOLDER(FILE_ID)));
	else
		SQLITE3_BIND_INT("insert_mmap_info", int, FILE_ID, file_id);

	err = sqlite3_step(ppStmt);
	// ASSERT(err == SQLITE_ROW, "insert_mmap_info: err != SQLITE_ROW");
	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_RETRY;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

//static int find_socket_by_inode(sqlite3* db, hashtable_t* ht, unsigned long inode) {
//	sqlite3_stmt* ppStmt;
//	int err, event_id;
//
//	ppStmt = (sqlite3_stmt *)hash_get(ht, SELECT_SOCKET_BY_INODE, sizeof(SELECT_SOCKET_BY_INODE));
//	if (ppStmt == NULL) {
//		fprintf(stderr, "find_socket_by_inode: Failed to acquire prepared statement from hashmap\n");
//		return CODE_FAILED;
//	}
//
//	SQLITE3_BIND_INT("find_socket_by_inode", int64, INODE_NUMBER, inode);
//
//	err = sqlite3_step(ppStmt);
//	if (err == SQLITE_ROW)
//		event_id = sqlite3_column_int(ppStmt, 0);
//	else
//		event_id = CODE_FAILED;
//
//	sqlite3_clear_bindings(ppStmt);
//	sqlite3_reset(ppStmt);
//
//	return event_id;
//}

int insert_proc_info(sqlite3 *db, hashtable_t *ht, struct message_state *ms,
		     int event_id, int file_id)
{
	sqlite3_stmt *ppStmt;
	unsigned long sock_id;
	enum STD_TYPE sock_type;
	int err;
	struct process_info *pinfo = NULL;
	char *string_data = NULL;
	char *args = NULL;
	char *env = NULL;
	uint32_t argv_off, env_off;

	ppStmt = hash_get(ht, INSERT_PROCESS_INFO, sizeof(INSERT_PROCESS_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_proc_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	pinfo = (struct process_info *)ms->primary_data;
	if (pinfo == NULL)
		return CODE_FAILED;

	string_data = MESSAGE_STRING(ms);
	if (string_data == NULL)
		return CODE_FAILED;

	SQLITE3_BIND_INT("insert_proc_info", int, EVENT_ID, event_id);
	SQLITE3_BIND_INT("insert_proc_info", int, FILE_ID, file_id);
	SQLITE3_BIND_INT("insert_proc_info", int64, PARENT_TGID,
			 (pinfo->ppid >> 32) & 0xFFFFFFFF);
	SQLITE3_BIND_INT("insert_proc_info", int64, PARENT_PID,
			 pinfo->ppid & 0xFFFFFFFF);
	SQLITE3_BIND_INT("insert_proc_info", int, UID, pinfo->credentials.uid);
	SQLITE3_BIND_INT("insert_proc_info", int, GID, pinfo->credentials.gid);
	SQLITE3_BIND_INT("insert_proc_info", int, EUID,
			 pinfo->credentials.euid);
	SQLITE3_BIND_INT("insert_proc_info", int, EGID,
			 pinfo->credentials.egid);

	/* save clone_flags if fork/clone */
	if (IS_FORK_OR_FRIENDS(pinfo->eh.syscall_nr)) {
		SQLITE3_BIND_INT("insert_proc_info", int64, CLONE_FLAGS,
				 pinfo->clone_flags);
	} else {
		sqlite3_bind_null(ppStmt,
				  sqlite3_bind_parameter_index(
					  ppStmt, PARAM_HOLDER(CLONE_FLAGS)));
	}

	/* save interpreter string */
	if (pinfo->interp_str_offset == LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE))
		sqlite3_bind_null(ppStmt,
				  sqlite3_bind_parameter_index(
					  ppStmt, PARAM_HOLDER(INTERPRETER)));
	else
		SQLITE3_BIND_STR("insert_proc_info", text, INTERPRETER,
				 &(string_data[pinfo->interp_str_offset]));

	/* save arguments */
	argv_off = pinfo->args.argv_offset;
	ASSERT(argv_off < PER_CPU_STR_BUFFSIZE,
	       "insert_proc_info: argv_off >= PER_CPU_STR_BUFFSIZE");
	if (pinfo->args.present == 0) {
		sqlite3_bind_null(ppStmt, sqlite3_bind_parameter_index(
						  ppStmt, PARAM_HOLDER(ARGS)));
	} else {
		args = build_cmdline(string_data, argv_off, pinfo->args.nbytes);
		if (args != NULL)
			SQLITE3_BIND_STR("insert_proc_info", text, ARGS, args);
		else
			sqlite3_bind_null(ppStmt,
					  sqlite3_bind_parameter_index(
						  ppStmt, PARAM_HOLDER(ARGS)));
	}

	/* save environment variables */
	env_off = pinfo->env.env_offset;
	ASSERT(env_off < PER_CPU_STR_BUFFSIZE,
	       "insert_proc_info: env_off >= PER_CPU_STR_BUFFSIZE");
	if (pinfo->env.present == 0) {
		sqlite3_bind_null(ppStmt, sqlite3_bind_parameter_index(
						  ppStmt, PARAM_HOLDER(ENV)));
	} else {
		env = build_env(string_data, env_off, pinfo->env.nbytes);
		if (env != NULL)
			SQLITE3_BIND_STR("insert_proc_info", text, ENV, env);
		else
			sqlite3_bind_null(ppStmt,
					  sqlite3_bind_parameter_index(
						  ppStmt, PARAM_HOLDER(ENV)));
	}

	/* Save standard input, output, err if sockets */
	sock_id = pinfo->io[STDIN_INDX].std_ino;
	sock_type = sock_id == 0 ? STD_NONE : pinfo->io[STDIN_INDX].type;
	SQLITE3_BIND_INT("insert_proc_info", int64, STDIN_INODE, sock_id);
	SQLITE3_BIND_INT("insert_proc_info", int, STDIN_TYPE, sock_type);

	sock_id = pinfo->io[STDOUT_INDX].std_ino;
	sock_type = sock_id == 0 ? STD_NONE : pinfo->io[STDOUT_INDX].type;
	SQLITE3_BIND_INT("insert_proc_info", int64, STDOUT_INODE, sock_id);
	SQLITE3_BIND_INT("insert_proc_info", int, STDOUT_TYPE, sock_type);

	sock_id = pinfo->io[STDERR_INDX].std_ino;
	sock_type = sock_id == 0 ? STD_NONE : pinfo->io[STDERR_INDX].type;
	SQLITE3_BIND_INT("insert_proc_info", int64, STDERR_INODE, sock_id);
	SQLITE3_BIND_INT("insert_proc_info", int, STDERR_TYPE, sock_type);

	err = sqlite3_step(ppStmt);
	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_RETRY;

	// clear binding and reset
	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	if (args != NULL)
		free(args);

	return err;
}

int insert_socket_create_info(sqlite3 *db, hashtable_t *ht,
			      struct message_state *ms, int event_id)
{
	sqlite3_stmt *ppStmt;
	struct socket_create *sock_info;
	int err;

	ppStmt = (sqlite3_stmt *)hash_get(ht, INSERT_SOCKET_CREATE_INFO,
					  sizeof(INSERT_SOCKET_CREATE_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_socket_create_info: failed to acquire prepared statement from hashmap\n");
		return CODE_FAILED;
	}

	sock_info = (struct socket_create *)ms->primary_data;

	SQLITE3_BIND_INT("insert_socket_create_info", int, EVENT_ID, event_id);
	SQLITE3_BIND_INT("insert_socket_create_info", int64, INODE_NUMBER,
			 sock_info->i_ino);

	char *family = socket_family_str(sock_info->family);
	if (family == NULL)
		return CODE_FAILED;

	char *type = socket_type_str(sock_info->type);
	ASSERT(type != NULL, "insert_socket_create_info: type == NULL");

	SQLITE3_BIND_STR("insert_socket_create_info", text, FAMILY, family);
	SQLITE3_BIND_STR("insert_socket_create_info", text, SOCK_TYPE, type);

	err = sqlite3_step(ppStmt);
	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_RETRY;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

int insert_tcp_conn_info(sqlite3 *db, hashtable_t *ht, struct message_state *ms,
			 int event_id)
{
	sqlite3_stmt *ppStmt;
	tcp_info_t *t;
	int err;
	char type[5] = { 0 };
	char saddrp[50] = { 0 };
	char daddrp[50] = { 0 };
	void *saddrn;
	void *daddrn;
	uint16_t dport, sport;
	char direction[16] = { 0 };

	ppStmt = (sqlite3_stmt *)hash_get(ht, INSERT_TCP_CONN_INFO,
					  sizeof(INSERT_TCP_CONN_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_tcp_conn_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	t = (tcp_info_t *)ms->primary_data;

	switch (t->t4.type) {
	case AF_INET:
		memcpy(type, "ipv4", sizeof(type));
		saddrn = &t->t4.saddr;
		daddrn = &t->t4.daddr;
		sport = t->t4.sport;
		dport = t->t4.dport;
		break;
	case AF_INET6:
		memcpy(type, "ipv6", sizeof(type));
		saddrn = t->t6.saddr;
		daddrn = t->t6.daddr;
		sport = t->t6.sport;
		dport = t->t6.dport;
		break;
	default:
		fprintf(stderr,
			"insert_tcp_conn_info: Invalid value of type\n");
		return CODE_FAILED;
	}

	if (t->t4.eh.syscall_nr == SYS_CONNECT)
		memcpy(direction, "outgoing\0", 10UL);
	else if (t->t4.eh.syscall_nr == SYS_ACCEPT)
		memcpy(direction, "incoming\0", 10UL);
	else
		fprintf(stderr,
			"insert_tcp_conn_info: Unexpected syscall number\n");

	inet_ntop((int)t->t4.type, saddrn, saddrp, 50);
	inet_ntop((int)t->t4.type, daddrn, daddrp, 50);

	SQLITE3_BIND_INT("insert_tcp_conn_info", int, EVENT_ID, event_id);
	SQLITE3_BIND_STR("insert_tcp_conn_info", text, SADDR, saddrp);
	SQLITE3_BIND_STR("insert_tcp_conn_info", text, DADDR, daddrp);
	SQLITE3_BIND_INT("insert_tcp_conn_info", int, SPORT, sport);
	SQLITE3_BIND_INT("insert_tcp_conn_info", int, DPORT, dport);
	SQLITE3_BIND_STR("insert_tcp_conn_info", text, TYPE, type);
	SQLITE3_BIND_STR("insert_tcp_conn_info", text, DIRECTION, direction);
	SQLITE3_BIND_INT("insert_tcp_conn_info", int64, SOCK_INODE,
			 t->t4.i_ino);

	//	sock_event_id = find_socket_by_inode(db, ht, t->t4.i_ino);
	//	if (sock_event_id == CODE_FAILED) {
	//		err = CODE_FAILED;
	//		goto fail;
	//	}

	err = sqlite3_step(ppStmt);
	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_RETRY;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

//int insert_fork_and_friends_event(sqlite3 *db, hashtable_t *ht,
//				  struct message_state *ms, int event_id)
//{
//	sqlite3_stmt *ppStmt;
//	struct child_proc_info *cpi;
//	int err;
//
//	ppStmt = (sqlite3_stmt *)hash_get(ht, INSERT_FORK_AND_FRIENDS_INFO,
//					  sizeof(INSERT_FORK_AND_FRIENDS_INFO));
//	if (ppStmt == NULL) {
//		fprintf(stderr,
//			"insert_fork_and_friends_event: Failed to acquire prepared statement from hashmap.\n");
//		return CODE_FAILED;
//	}
//
//	cpi = (struct child_proc_info *)ms->primary_data;
//
//	SQLITE3_BIND_INT("insert_fork_and_friends_event", int, EVENT_ID,
//			 event_id);
//	SQLITE3_BIND_INT("insert_fork_and_friends_event", int64, NEW_TGID_PID,
//			 cpi->tgid_pid);
//	SQLITE3_BIND_INT("insert_fork_and_friends_event", int64, PPID,
//			 cpi->ppid);
//	SQLITE3_BIND_INT("insert_fork_and_friends_event", int64, CLONE_FLAGS,
//			 cpi->clone_flags);
//
//	err = sqlite3_step(ppStmt);
//	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_RETRY;
//
//	sqlite3_clear_bindings(ppStmt);
//	sqlite3_reset(ppStmt);
//
//	return err;
//}

int insert_lpe_info(sqlite3 *db, hashtable_t *ht, struct message_state *ms,
		    int event_id)
{
	sqlite3_stmt *ppStmt;
	struct cfg_integrity *cfg;
	int err;

	ppStmt = (sqlite3_stmt *)hash_get(ht, INSERT_LPE_INFO,
					  sizeof(INSERT_LPE_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_lpe_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	cfg = (struct cfg_integrity *)ms->primary_data;
	SQLITE3_BIND_INT("insert_lpe_info", int, EVENT_ID, event_id);
	SQLITE3_BIND_INT("insert_lpe_info", int64, CALLER_RET_ADDR,
			 cfg->caller_addr);
	SQLITE3_BIND_STR("insert_lpe_info", text, TARGET_FUNC, "commit_creds");

	err = sqlite3_step(ppStmt);
	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_RETRY;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

int insert_ptrace_event(sqlite3 *db, hashtable_t *ht, struct message_state *ms,
			int event_id)
{
	sqlite3_stmt *ppStmt;
	struct ptrace_event_info *ptrace_info;
	int err;
	u64_t target_tgid;
	u64_t target_pid;

	ppStmt = (sqlite3_stmt *)hash_get(ht, INSERT_PTRACE_INFO,
					  sizeof(INSERT_PTRACE_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_ptrace_event: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	ptrace_info = (struct ptrace_event_info *)ms->primary_data;
	target_tgid = (ptrace_info->target_tgid_pid >> 32) & 0xFFFFFFFF;
	target_pid = ptrace_info->target_tgid_pid & 0xFFFFFFFF;

	SQLITE3_BIND_INT("insert_ptrace_event", int, EVENT_ID, event_id);
	SQLITE3_BIND_INT("insert_ptrace_event", int64, REQUEST,
			 ptrace_info->request);
	SQLITE3_BIND_INT("insert_ptrace_event", int64, ADDR, ptrace_info->addr);
	SQLITE3_BIND_INT("insert_ptrace_event", int64, TARGET_TGID,
			 target_tgid);
	SQLITE3_BIND_INT("insert_ptrace_event", int64, TARGET_PID, target_pid);

	err = sqlite3_step(ppStmt);
	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_RETRY;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

int insert_kernel_module_info(sqlite3 *db, hashtable_t *ht, int file_id,
			      int event_id)
{
	int err;
	sqlite3_stmt *ppStmt;

	ppStmt = (sqlite3_stmt *)hash_get(ht, INSERT_MODULE_INFO,
					  sizeof(INSERT_MODULE_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_kernel_module_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	SQLITE3_BIND_INT("insert_kernel_module_info", int, EVENT_ID, event_id);
	SQLITE3_BIND_INT("insert_kernel_module_info", int, FILE_ID, file_id);

	err = sqlite3_step(ppStmt);
	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_RETRY;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

int insert_modprobe_overwrite_info(sqlite3 *db, hashtable_t *ht,
				   struct message_state *ms, int event_id)
{
	int err;
	struct modprobe_overwrite *mwrite;
	sqlite3_stmt *ppStmt;

	ppStmt = (sqlite3_stmt *)hash_get(
		ht, INSERT_MODPROBE_OVERWRITE_INFO,
		sizeof(INSERT_MODPROBE_OVERWRITE_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"insert_modprobe_overwrite_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	mwrite = (struct modprobe_overwrite *)ms->primary_data;

	SQLITE3_BIND_INT("insert_modprobe_overwrite_info", int, EVENT_ID,
			 event_id);
	SQLITE3_BIND_STR("insert_modprobe_overwrite_info", text, PATH_NAME,
			 mwrite->new_path);

	err = sqlite3_step(ppStmt);
	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_FAILED;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

int select_all_process_info(sqlite3 *db, hashtable_t *ht,
			    lua_process_info_array *process_info_arr, int tgid)
{
	int err;
	sqlite3_stmt *ppStmt;
	u64_t tmp_event_time;
	u64_t tmp_parent_tgid;
	int tmp_syscall;
	const unsigned char *tmp_process_name;
	int tmp_process_name_len;
	struct lua_process_info **tmp_values;
	u64_t tmp_clone_flags;
	const unsigned char *tmp_args;
	int tmp_args_len;
	const unsigned char *tmp_env;
	int tmp_env_len;
	const unsigned char *tmp_interpreter;
	int tmp_interpreter_len;
	int tmp_uid;
	int tmp_gid;
	int tmp_euid;
	int tmp_egid;
	int tmp_stdin_inode;
	int tmp_stdin_type;
	int tmp_stdout_inode;
	int tmp_stdout_type;
	int tmp_stderr_inode;
	int tmp_stderr_type;
	const unsigned char *tmp_filename;
	int tmp_filename_len;
	u64_t tmp_inode;
	u64_t tmp_s_magic;

	ASSERT(process_info_arr != NULL,
	       "select_all_process_info: process_info_arr is NULL");
	ASSERT(process_info_arr->values != NULL,
	       "select_all_process_info: process_info_arr->values is NULL");
	ASSERT(process_info_arr->size == 0,
	       "select_all_process_info: process_info_arr is non-empty");

	ppStmt = (sqlite3_stmt *)hash_get(ht, SELECT_PROCESS_INFO,
					  sizeof(SELECT_PROCESS_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"select_all_process_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	SQLITE3_BIND_INT("select_all_process_info", int, TGID, tgid);

	while (true) {
		err = sqlite3_step(ppStmt);
		if (err != SQLITE_ROW) {
			break;
		}
		if (err == SQLITE_ROW) {
			if (process_info_arr->size ==
			    process_info_arr->max_size) {
				process_info_arr->max_size +=
					PROCESS_INFO_CHUNK_SIZE;
				tmp_values =
					realloc(process_info_arr->values,
						sizeof(struct process_info) *
							(size_t)process_info_arr
								->max_size);
				if (tmp_values == NULL) {
					fprintf(stderr,
						"select_all_process_info: Failed to realloc memory for process_info_arr->values\n");
					sqlite3_clear_bindings(ppStmt);
					sqlite3_reset(ppStmt);
					return CODE_FAILED;
				}
				process_info_arr->values = tmp_values;
			}
			process_info_arr->size += 1;
			SQLITE3_GET(tmp_event_time, int64, 0);
			SQLITE3_GET(tmp_syscall, int, 1);
			SQLITE3_GET(tmp_process_name, text, 2);
			SQLITE3_GET(tmp_parent_tgid, int64, 3);
			SQLITE3_GET(tmp_clone_flags, int64, 4);
			SQLITE3_GET(tmp_args, text, 5);
			SQLITE3_GET(tmp_env, text, 6);
			SQLITE3_GET(tmp_interpreter, text, 7);
			SQLITE3_GET(tmp_uid, int, 8);
			SQLITE3_GET(tmp_gid, int, 9);
			SQLITE3_GET(tmp_euid, int, 10);
			SQLITE3_GET(tmp_egid, int, 11);
			SQLITE3_GET(tmp_stdin_inode, int, 12);
			SQLITE3_GET(tmp_stdin_type, int, 13);
			SQLITE3_GET(tmp_stdout_inode, int, 14);
			SQLITE3_GET(tmp_stdout_type, int, 15);
			SQLITE3_GET(tmp_stderr_inode, int, 16);
			SQLITE3_GET(tmp_stderr_type, int, 17);
			SQLITE3_GET(tmp_filename, text, 18);
			SQLITE3_GET(tmp_inode, int64, 19);
			SQLITE3_GET(tmp_s_magic, int64, 20);
			tmp_process_name_len =
				(int)strlen((const char *)tmp_process_name) + 1;

			if (tmp_args == NULL) {
				tmp_args = "";
			}
			tmp_args_len = (int)strlen((const char *)tmp_args) + 1;
			if (tmp_env == NULL) {
				tmp_env = "";
			}
			tmp_env_len = (int)strlen((const char *)tmp_env) + 1;
			if (tmp_interpreter == NULL) {
				tmp_interpreter = "";
			}
			tmp_interpreter_len =
				(int)strlen((const char *)tmp_interpreter) + 1;
			tmp_filename_len =
				(int)strlen((const char *)tmp_filename) + 1;

			process_info_arr->values[process_info_arr->size - 1] =
				(struct lua_process_info *)malloc(
					sizeof(struct lua_process_info));
			process_info_arr->values[process_info_arr->size - 1]
				->event_info = (struct lua_event_info *)malloc(
				sizeof(struct lua_event_info));
			process_info_arr->values[process_info_arr->size - 1]
				->event_info->process_name = (char *)malloc(
				(sizeof(char) * (size_t)tmp_process_name_len));
			strlcpy(process_info_arr
					->values[process_info_arr->size - 1]
					->event_info->process_name,
				(const char *)tmp_process_name,
				(size_t)tmp_process_name_len);
			process_info_arr->values[process_info_arr->size - 1]
				->event_info->event_time = tmp_event_time;
			process_info_arr->values[process_info_arr->size - 1]
				->event_info->syscall = tmp_syscall;

			process_info_arr->values[process_info_arr->size - 1]
				->parent_tgid = tmp_parent_tgid;
			process_info_arr->values[process_info_arr->size - 1]
				->args = (char *)malloc(
				(sizeof(char) * (size_t)tmp_args_len));
			strlcpy(process_info_arr
					->values[process_info_arr->size - 1]
					->args,
				(const char *)tmp_args, (size_t)tmp_args_len);
			process_info_arr->values[process_info_arr->size - 1]
				->env = (char *)malloc(
				(sizeof(char) * (size_t)tmp_env_len));
			strlcpy(process_info_arr
					->values[process_info_arr->size - 1]
					->env,
				(const char *)tmp_env, (size_t)tmp_env_len);
			process_info_arr->values[process_info_arr->size - 1]
				->interpreter = (char *)malloc(
				(sizeof(char) * (size_t)tmp_interpreter_len));
			strlcpy(process_info_arr
					->values[process_info_arr->size - 1]
					->interpreter,
				(const char *)tmp_interpreter,
				(size_t)tmp_interpreter_len);

			process_info_arr->values[process_info_arr->size - 1]
				->clone_flags = tmp_clone_flags;
			process_info_arr->values[process_info_arr->size - 1]
				->uid = tmp_uid;
			process_info_arr->values[process_info_arr->size - 1]
				->gid = tmp_gid;
			process_info_arr->values[process_info_arr->size - 1]
				->euid = tmp_euid;
			process_info_arr->values[process_info_arr->size - 1]
				->egid = tmp_egid;
			process_info_arr->values[process_info_arr->size - 1]
				->stdin_inode = tmp_stdin_inode;
			process_info_arr->values[process_info_arr->size - 1]
				->stdout_inode = tmp_stdout_inode;
			process_info_arr->values[process_info_arr->size - 1]
				->stderr_inode = tmp_stderr_inode;
			process_info_arr->values[process_info_arr->size - 1]
				->stdin_type = tmp_stdin_type;
			process_info_arr->values[process_info_arr->size - 1]
				->stdout_type = tmp_stdout_type;
			process_info_arr->values[process_info_arr->size - 1]
				->stderr_type = tmp_stderr_type;

			process_info_arr->values[process_info_arr->size - 1]
				->file_info = (struct lua_file_info *)malloc(
				sizeof(struct lua_file_info));
			process_info_arr->values[process_info_arr->size - 1]
				->file_info->filename = (char *)malloc(
				(sizeof(char) * (size_t)tmp_filename_len));
			strlcpy(process_info_arr
					->values[process_info_arr->size - 1]
					->file_info->filename,
				(const char *)tmp_filename,
				(size_t)tmp_filename_len);
			process_info_arr->values[process_info_arr->size - 1]
				->file_info->inode = tmp_inode;
			process_info_arr->values[process_info_arr->size - 1]
				->file_info->s_magic = tmp_s_magic;
		}
	}

	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_FAILED;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

int select_all_mmap_info(sqlite3 *db, hashtable_t *ht,
			 lua_mmap_info_array *mmap_info_arr, int tgid)
{
	int err;
	sqlite3_stmt *ppStmt;
	u64_t tmp_event_time;
	u64_t tmp_vm_base;
	u64_t tmp_vm_flags;
	u64_t tmp_vm_prot;
	u64_t tmp_vm_len;
	int tmp_syscall;
	const unsigned char *tmp_process_name;
	int tmp_process_name_len;
	const unsigned char *tmp_filename;
	int tmp_filename_len;
	u64_t tmp_inode;
	u64_t tmp_s_magic;
	struct lua_mmap_info **tmp_values;

	ASSERT(mmap_info_arr != NULL,
	       "select_all_mmap_info: mmap_info_arr is NULL");
	ASSERT(mmap_info_arr->values != NULL,
	       "select_all_mmap_info: mmap_info_arr->values is NULL");
	ASSERT(mmap_info_arr->size == 0,
	       "select_all_mmap_info: mmap_info_arr is non-empty");

	ppStmt = (sqlite3_stmt *)hash_get(ht, SELECT_MMAP_INFO,
					  sizeof(SELECT_MMAP_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"select_all_mmap_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	SQLITE3_BIND_INT("select_all_mmap_info", int, TGID, tgid);

	while (true) {
		err = sqlite3_step(ppStmt);
		if (err != SQLITE_ROW) {
			break;
		}
		if (err == SQLITE_ROW) {
			if (mmap_info_arr->size == mmap_info_arr->max_size) {
				mmap_info_arr->max_size +=
					PROCESS_INFO_CHUNK_SIZE;
				tmp_values = realloc(
					mmap_info_arr->values,
					sizeof(struct process_info) *
						(size_t)mmap_info_arr->max_size);
				if (tmp_values == NULL) {
					fprintf(stderr,
						"select_all_mmap_info: Failed to realloc memory for mmap_info_arr->values\n");
					sqlite3_clear_bindings(ppStmt);
					sqlite3_reset(ppStmt);
					return CODE_FAILED;
				}
				mmap_info_arr->values = tmp_values;
			}
			mmap_info_arr->size += 1;
			SQLITE3_GET(tmp_event_time, int64, 0);
			SQLITE3_GET(tmp_syscall, int, 1);
			SQLITE3_GET(tmp_process_name, text, 2);
			tmp_process_name_len =
				(int)strlen((const char *)tmp_process_name) + 1;

			SQLITE3_GET(tmp_vm_base, int64, 3);
			SQLITE3_GET(tmp_vm_flags, int64, 4);
			SQLITE3_GET(tmp_vm_prot, int64, 5);
			SQLITE3_GET(tmp_vm_len, int64, 6);

			SQLITE3_GET(tmp_filename, text, 7);
			tmp_filename_len =
				(int)strlen((const char *)tmp_filename) + 1;
			SQLITE3_GET(tmp_inode, int64, 8);
			SQLITE3_GET(tmp_s_magic, int64, 9);

			mmap_info_arr->values[mmap_info_arr->size - 1] =
				(struct lua_mmap_info *)malloc(
					sizeof(struct lua_mmap_info));
			mmap_info_arr->values[mmap_info_arr->size - 1]
				->event_info = (struct lua_event_info *)malloc(
				sizeof(struct lua_event_info));
			mmap_info_arr->values[mmap_info_arr->size - 1]
				->event_info->process_name = (char *)malloc(
				(sizeof(char) * (size_t)tmp_process_name_len));
			mmap_info_arr->values[mmap_info_arr->size - 1]
				->event_info->event_time = tmp_event_time;
			mmap_info_arr->values[mmap_info_arr->size - 1]
				->event_info->syscall = tmp_syscall;
			strlcpy(mmap_info_arr->values[mmap_info_arr->size - 1]
					->event_info->process_name,
				(const char *)tmp_process_name,
				(size_t)tmp_process_name_len);

			mmap_info_arr->values[mmap_info_arr->size - 1]->vm_base =
				tmp_vm_base;
			mmap_info_arr->values[mmap_info_arr->size - 1]
				->vm_flags = tmp_vm_flags;
			mmap_info_arr->values[mmap_info_arr->size - 1]->vm_prot =
				tmp_vm_prot;
			mmap_info_arr->values[mmap_info_arr->size - 1]->vm_len =
				tmp_vm_len;

			mmap_info_arr->values[mmap_info_arr->size - 1]
				->file_info = (struct lua_file_info *)malloc(
				sizeof(struct lua_file_info));
			mmap_info_arr->values[mmap_info_arr->size - 1]
				->file_info->filename = (char *)malloc(
				(sizeof(char) * (size_t)tmp_filename_len));
			strlcpy(mmap_info_arr->values[mmap_info_arr->size - 1]
					->file_info->filename,
				(const char *)tmp_filename,
				(size_t)tmp_filename_len);
			mmap_info_arr->values[mmap_info_arr->size - 1]
				->file_info->inode = tmp_inode;
			mmap_info_arr->values[mmap_info_arr->size - 1]
				->file_info->s_magic = tmp_s_magic;
		}
	}

	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_FAILED;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

int select_all_ptrace_info(sqlite3 *db, hashtable_t *ht,
			   lua_ptrace_info_array *ptrace_info_arr, int tgid)
{
	int err;
	sqlite3_stmt *ppStmt;
	u64_t tmp_event_time;
	u64_t tmp_request;
	u64_t tmp_addr;
	u64_t tmp_target_tgid;
	int tmp_syscall;
	const unsigned char *tmp_process_name;
	int tmp_process_name_len;
	struct lua_ptrace_info **tmp_values;

	ASSERT(ptrace_info_arr != NULL,
	       "select_all_ptrace_info: ptrace_info_arr is NULL");
	ASSERT(ptrace_info_arr->values != NULL,
	       "select_all_ptrace_info: ptrace_info_arr->values is NULL");
	ASSERT(ptrace_info_arr->size == 0,
	       "select_all_ptrace_info: ptrace_info_arr is non-empty");

	ppStmt = (sqlite3_stmt *)hash_get(ht, SELECT_PTRACE_INFO,
					  sizeof(SELECT_PTRACE_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"select_all_ptrace_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	SQLITE3_BIND_INT("select_all_ptrace_info", int, TGID, tgid);

	while (true) {
		err = sqlite3_step(ppStmt);
		if (err != SQLITE_ROW) {
			break;
		}
		if (err == SQLITE_ROW) {
			if (ptrace_info_arr->size ==
			    ptrace_info_arr->max_size) {
				ptrace_info_arr->max_size +=
					PROCESS_INFO_CHUNK_SIZE;
				tmp_values =
					realloc(ptrace_info_arr->values,
						sizeof(struct process_info) *
							(size_t)ptrace_info_arr
								->max_size);
				if (tmp_values == NULL) {
					fprintf(stderr,
						"select_all_ptrace_info: Failed to realloc memory for ptrace_info_arr->values\n");
					sqlite3_clear_bindings(ppStmt);
					sqlite3_reset(ppStmt);
					return CODE_FAILED;
				}
				ptrace_info_arr->values = tmp_values;
			}
			ptrace_info_arr->size += 1;
			SQLITE3_GET(tmp_event_time, int64, 0);
			SQLITE3_GET(tmp_syscall, int, 1);
			SQLITE3_GET(tmp_process_name, text, 2);
			tmp_process_name_len =
				(int)strlen((const char *)tmp_process_name) + 1;

			SQLITE3_GET(tmp_request, int64, 3);
			SQLITE3_GET(tmp_addr, int64, 4);
			SQLITE3_GET(tmp_target_tgid, int64, 5);

			ptrace_info_arr->values[ptrace_info_arr->size - 1] =
				(struct lua_ptrace_info *)malloc(
					sizeof(struct lua_ptrace_info));
			ptrace_info_arr->values[ptrace_info_arr->size - 1]
				->event_info = (struct lua_event_info *)malloc(
				sizeof(struct lua_event_info));
			ptrace_info_arr->values[ptrace_info_arr->size - 1]
				->event_info->process_name = (char *)malloc(
				(sizeof(char) * (size_t)tmp_process_name_len));
			ptrace_info_arr->values[ptrace_info_arr->size - 1]
				->event_info->event_time = tmp_event_time;
			ptrace_info_arr->values[ptrace_info_arr->size - 1]
				->event_info->syscall = tmp_syscall;
			strlcpy(ptrace_info_arr
					->values[ptrace_info_arr->size - 1]
					->event_info->process_name,
				(const char *)tmp_process_name,
				(size_t)tmp_process_name_len);

			ptrace_info_arr->values[ptrace_info_arr->size - 1]
				->request = tmp_request;
			ptrace_info_arr->values[ptrace_info_arr->size - 1]
				->addr = tmp_addr;
			ptrace_info_arr->values[ptrace_info_arr->size - 1]
				->target_tgid = tmp_target_tgid;
		}
	}

	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_FAILED;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

int select_all_socket_create_info(
	sqlite3 *db, hashtable_t *ht,
	lua_socket_create_info_array *socket_create_info_arr, int tgid)
{
	int err;
	sqlite3_stmt *ppStmt;
	u64_t tmp_event_time;
	u64_t tmp_inode;
	const unsigned char *tmp_family;
	int tmp_family_len;
	const unsigned char *tmp_sock_type;
	int tmp_sock_type_len;
	int tmp_syscall;
	const unsigned char *tmp_process_name;
	int tmp_process_name_len;
	struct lua_socket_create_info **tmp_values;

	ASSERT(socket_create_info_arr != NULL,
	       "select_all_socket_create_info: socket_create_info_arr is NULL");
	ASSERT(socket_create_info_arr->values != NULL,
	       "select_all_socket_create_info: socket_create_info_arr->values is NULL");
	ASSERT(socket_create_info_arr->size == 0,
	       "select_all_socket_create_info: socket_create_info_arr is non-empty");

	ppStmt = (sqlite3_stmt *)hash_get(ht, SELECT_SOCKET_CREATE_INFO,
					  sizeof(SELECT_SOCKET_CREATE_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"select_all_socket_create_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	SQLITE3_BIND_INT("select_all_socket_create_info", int, TGID, tgid);

	while (true) {
		err = sqlite3_step(ppStmt);
		if (err != SQLITE_ROW) {
			break;
		}
		if (err == SQLITE_ROW) {
			if (socket_create_info_arr->size ==
			    socket_create_info_arr->max_size) {
				socket_create_info_arr->max_size +=
					PROCESS_INFO_CHUNK_SIZE;
				tmp_values = realloc(
					socket_create_info_arr->values,
					sizeof(struct process_info) *
						(size_t)socket_create_info_arr
							->max_size);
				if (tmp_values == NULL) {
					fprintf(stderr,
						"select_all_socket_create_info: Failed to realloc memory for socket_create_info_arr->values\n");
					sqlite3_clear_bindings(ppStmt);
					sqlite3_reset(ppStmt);
					return CODE_FAILED;
				}
				socket_create_info_arr->values = tmp_values;
			}
			socket_create_info_arr->size += 1;
			SQLITE3_GET(tmp_event_time, int64, 0);
			SQLITE3_GET(tmp_syscall, int, 1);
			SQLITE3_GET(tmp_process_name, text, 2);
			tmp_process_name_len =
				(int)strlen((const char *)tmp_process_name) + 1;

			SQLITE3_GET(tmp_inode, int64, 3);
			SQLITE3_GET(tmp_family, text, 4);
			if (tmp_family == NULL) {
				tmp_family = "";
			}
			tmp_family_len =
				(int)strlen((const char *)tmp_family) + 1;
			SQLITE3_GET(tmp_sock_type, text, 5);
			if (tmp_sock_type == NULL) {
				tmp_sock_type = "";
			}
			tmp_sock_type_len =
				(int)strlen((const char *)tmp_sock_type) + 1;

			socket_create_info_arr
				->values[socket_create_info_arr->size - 1] =
				(struct lua_socket_create_info *)malloc(
					sizeof(struct lua_socket_create_info));
			socket_create_info_arr
				->values[socket_create_info_arr->size - 1]
				->event_info = (struct lua_event_info *)malloc(
				sizeof(struct lua_event_info));
			socket_create_info_arr
				->values[socket_create_info_arr->size - 1]
				->event_info->process_name = (char *)malloc(
				(sizeof(char) * (size_t)tmp_process_name_len));
			socket_create_info_arr
				->values[socket_create_info_arr->size - 1]
				->event_info->event_time = tmp_event_time;
			socket_create_info_arr
				->values[socket_create_info_arr->size - 1]
				->event_info->syscall = tmp_syscall;
			strlcpy(socket_create_info_arr
					->values[socket_create_info_arr->size -
						 1]
					->event_info->process_name,
				(const char *)tmp_process_name,
				(size_t)tmp_process_name_len);

			socket_create_info_arr
				->values[socket_create_info_arr->size - 1]
				->inode = tmp_inode;
			socket_create_info_arr
				->values[socket_create_info_arr->size - 1]
				->family = (char *)malloc(
				(sizeof(char) * (size_t)tmp_family_len));
			strlcpy(socket_create_info_arr
					->values[socket_create_info_arr->size -
						 1]
					->family,
				(const char *)tmp_family,
				(size_t)tmp_family_len);
			socket_create_info_arr
				->values[socket_create_info_arr->size - 1]
				->socket_type = (char *)malloc(
				(sizeof(char) * (size_t)tmp_sock_type_len));
			strlcpy(socket_create_info_arr
					->values[socket_create_info_arr->size -
						 1]
					->socket_type,
				(const char *)tmp_sock_type,
				(size_t)tmp_sock_type_len);
		}
	}

	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_FAILED;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}

int select_all_tcp_connection_info(
	sqlite3 *db, hashtable_t *ht,
	lua_tcp_connection_info_array *tcp_connection_info_arr, int tgid)
{
	int err;
	sqlite3_stmt *ppStmt;
	u64_t tmp_event_time;
	u64_t tmp_inode;
	const unsigned char *tmp_direction;
	int tmp_src_port;
	int tmp_dst_port;
	const unsigned char *tmp_src_addr;
	int tmp_src_addr_len;
	const unsigned char *tmp_dst_addr;
	int tmp_dst_addr_len;
	const unsigned char *tmp_inet_type;
	int tmp_inet_type_len;
	int tmp_syscall;
	const unsigned char *tmp_process_name;
	int tmp_process_name_len;
	struct lua_tcp_connection_info **tmp_values;

	ASSERT(tcp_connection_info_arr != NULL,
	       "select_all_tcp_connection_info: tcp_connection_info_arr is NULL");
	ASSERT(tcp_connection_info_arr->values != NULL,
	       "select_all_tcp_connection_info: tcp_connection_info_arr->values is NULL");
	ASSERT(tcp_connection_info_arr->size == 0,
	       "select_all_tcp_connection_info: tcp_connection_info_arr is non-empty");

	ppStmt = (sqlite3_stmt *)hash_get(ht, SELECT_TCP_CONNECTION_INFO,
					  sizeof(SELECT_TCP_CONNECTION_INFO));
	if (ppStmt == NULL) {
		fprintf(stderr,
			"select_all_tcp_connection_info: Failed to acquire prepared statement from hashmap.\n");
		return CODE_FAILED;
	}

	SQLITE3_BIND_INT("select_all_tcp_connection_info", int, TGID, tgid);

	while (true) {
		err = sqlite3_step(ppStmt);
		if (err != SQLITE_ROW) {
			break;
		}
		if (err == SQLITE_ROW) {
			if (tcp_connection_info_arr->size ==
			    tcp_connection_info_arr->max_size) {
				tcp_connection_info_arr->max_size +=
					PROCESS_INFO_CHUNK_SIZE;
				tmp_values = realloc(
					tcp_connection_info_arr->values,
					sizeof(struct process_info) *
						(size_t)tcp_connection_info_arr
							->max_size);
				if (tmp_values == NULL) {
					fprintf(stderr,
						"select_all_tcp_connection_info: Failed to realloc memory for tcp_connection_info_arr->values\n");
					sqlite3_clear_bindings(ppStmt);
					sqlite3_reset(ppStmt);
					return CODE_FAILED;
				}
				tcp_connection_info_arr->values = tmp_values;
			}
			tcp_connection_info_arr->size += 1;
			SQLITE3_GET(tmp_event_time, int64, 0);
			SQLITE3_GET(tmp_syscall, int, 1);
			SQLITE3_GET(tmp_process_name, text, 2);
			tmp_process_name_len =
				(int)strlen((const char *)tmp_process_name) + 1;

			SQLITE3_GET(tmp_inet_type, text, 3);
			if (tmp_inet_type == NULL) {
				tmp_inet_type = "";
			}
			tmp_inet_type_len =
				(int)strlen((const char *)tmp_inet_type) + 1;

			SQLITE3_GET(tmp_direction, text, 8);
			SQLITE3_GET(tmp_inode, int64, 9);
			if (strcmp(tmp_direction, "outgoing") == 0) {
				SQLITE3_GET(tmp_src_addr, text, 4);
				if (tmp_src_addr == NULL) {
					tmp_src_addr = "";
				}
				tmp_src_addr_len =
					(int)strlen(
						(const char *)tmp_src_addr) +
					1;
				SQLITE3_GET(tmp_src_port, int, 5);

				SQLITE3_GET(tmp_dst_addr, text, 6);
				if (tmp_dst_addr == NULL) {
					tmp_dst_addr = "";
				}
				tmp_dst_addr_len =
					(int)strlen(
						(const char *)tmp_dst_addr) +
					1;
				SQLITE3_GET(tmp_dst_port, int, 7);
			} else if (strcmp(tmp_direction, "incoming") == 0) {
				SQLITE3_GET(tmp_src_addr, text, 6);
				if (tmp_src_addr == NULL) {
					tmp_src_addr = "";
				}
				tmp_src_addr_len =
					(int)strlen(
						(const char *)tmp_src_addr) +
					1;
				SQLITE3_GET(tmp_src_port, int, 7);

				SQLITE3_GET(tmp_dst_addr, text, 4);
				if (tmp_dst_addr == NULL) {
					tmp_dst_addr = "";
				}
				tmp_dst_addr_len =
					(int)strlen(
						(const char *)tmp_dst_addr) +
					1;
				SQLITE3_GET(tmp_dst_port, int, 5);
			} else {
				fprintf(stderr,
					"select_all_tcp_connection_info: Unknown direction: %s\n",
					tmp_direction);
				sqlite3_clear_bindings(ppStmt);
				sqlite3_reset(ppStmt);
				return CODE_FAILED;
			}

			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1] =
				(struct lua_tcp_connection_info *)malloc(
					sizeof(struct lua_tcp_connection_info));
			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->event_info = (struct lua_event_info *)malloc(
				sizeof(struct lua_event_info));
			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->event_info->process_name = (char *)malloc(
				(sizeof(char) * (size_t)tmp_process_name_len));
			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->event_info->event_time = tmp_event_time;
			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->event_info->syscall = tmp_syscall;
			strlcpy(tcp_connection_info_arr
					->values[tcp_connection_info_arr->size -
						 1]
					->event_info->process_name,
				(const char *)tmp_process_name,
				(size_t)tmp_process_name_len);

			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->inode = tmp_inode;
			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->type = (char *)malloc(
				(sizeof(char) * (size_t)tmp_inet_type_len));
			strlcpy(tcp_connection_info_arr
					->values[tcp_connection_info_arr->size -
						 1]
					->type,
				(const char *)tmp_inet_type,
				(size_t)tmp_inet_type_len);

			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->src_addr = (char *)malloc(
				(sizeof(char) * (size_t)tmp_src_addr_len));
			strlcpy(tcp_connection_info_arr
					->values[tcp_connection_info_arr->size -
						 1]
					->src_addr,
				(const char *)tmp_src_addr,
				(size_t)tmp_src_addr_len);
			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->dst_addr = (char *)malloc(
				(sizeof(char) * (size_t)tmp_dst_addr_len));
			strlcpy(tcp_connection_info_arr
					->values[tcp_connection_info_arr->size -
						 1]
					->dst_addr,
				(const char *)tmp_dst_addr,
				(size_t)tmp_dst_addr_len);
			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->src_port = tmp_src_port;
			tcp_connection_info_arr
				->values[tcp_connection_info_arr->size - 1]
				->dst_port = tmp_dst_port;
		}
	}

	err = err == SQLITE_DONE ? CODE_SUCCESS : CODE_FAILED;

	sqlite3_clear_bindings(ppStmt);
	sqlite3_reset(ppStmt);

	return err;
}
