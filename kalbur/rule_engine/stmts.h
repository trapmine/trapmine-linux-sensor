/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file defines various sql statements used in the projects.
 * It also defines some structs for working with these statements.
 */

#ifndef STMTS_H
#define STMTS_H

#include <stddef.h>
#include <schema.h>
#include <sqlite3.h>
#include "helper_defs.h"

const char *CREATE_STMTS[] = {
	EVENTS_TABLE,
	FILE_INFO_TABLE,
	PROCESS_MMAP_TABLE,
	PROCESS_INFO_TABLE,
	CHILD_PROC_INFO_TABLE,
	TCP_CONNECTION_TABLE,
	SOCKET_CREATE_TABLE,
	LPE_TABLE,
	PTRACE_TABLE,
	DISALLOWED_TABLE,
	KERNEL_MODULE_LOAD_TABLE,
	MODPROBE_OVERWRITE_TABLE,
};

#define N_CREATE_STMTS (sizeof(CREATE_STMTS) / sizeof(CREATE_STMTS[0]))

// ########################
// ####### PRAGMAS ########
// ########################
#define JOURNAL_MODE "pragma journal_mode = WAL;"
#define SYNCHRONOUS "pragma synchronous = normal;"
#define TEMP_STORE "pragma temp_store = memory;"
#define MMAP_SIZE "pragma mmap_size = 30000000000;"

// ########################
// #### SQL STATEMENTS ####
// ########################

char INSERT_EVENT[] = "INSERT INTO events(\
				" EVENT_TIME "," TGID_PID "," SYSCALL "," COMM
		      ") \
				VALUES(:" EVENT_TIME ",:" TGID_PID ",:" SYSCALL
		      ",:" COMM ") RETURNING " EVENT_ID ";";

char INSERT_FILE_INFO[] = "INSERT INTO file_info(\
					" FILENAME "," INODE_NUMBER "," S_MAGIC
			  ") \
					VALUES(:" FILENAME ",:" INODE_NUMBER
			  ",:" S_MAGIC ")\
					RETURNING " FILE_ID ";";

char INSERT_PROC_MMAP[] = "INSERT INTO proc_mmap(\
					" EVENT_ID "," FILE_ID "," VM_BASE
			  "," VM_FLAGS "," VM_PROT ", \
					" VM_LEN ") \
					VALUES(:" EVENT_ID ",:" FILE_ID
			  ",:" VM_BASE ",:" VM_FLAGS ",\
					:" VM_PROT ", :" VM_LEN ");";

char INSERT_FORK_AND_FRIENDS_INFO[] = "INSERT INTO child_proc_info(\
				       " EVENT_ID "," NEW_TGID_PID "," PPID
				      "," CLONE_FLAGS ") VALUES\
					(:" EVENT_ID ",:" NEW_TGID_PID ",:" PPID
				      ",:" CLONE_FLAGS ");";

char INSERT_PROCESS_INFO[] =
	"INSERT INTO process_info(\
					" EVENT_ID "," PPID "," FILE_ID "," ARGS
	"," INTERPRETER "," UID "," GID "," EUID "," EGID "," STDIN_INODE
	"," STDIN_TYPE "," STDOUT_INODE "," STDOUT_TYPE "," STDERR_INODE
	"," STDERR_TYPE ") VALUES(:" EVENT_ID ",:" PPID ",:" FILE_ID ",:" ARGS
	",:" INTERPRETER ",:" UID ",:" GID ",:" EUID ",:" EGID ",:" STDIN_INODE
	",:" STDIN_TYPE ",:" STDOUT_INODE ",:" STDOUT_TYPE ",:" STDERR_INODE
	",:" STDERR_TYPE ");";

char INSERT_SOCKET_CREATE_INFO[] =
	"INSERT INTO socket_create_info(\
				    " EVENT_ID "," INODE_NUMBER "," FAMILY
	"," SOCK_TYPE ") VALUES(:" EVENT_ID ",:" INODE_NUMBER ",:" FAMILY
	",:" SOCK_TYPE ");";

char INSERT_TCP_CONN_INFO[] =
	"INSERT INTO tcp_connection_info(\
			       	" EVENT_ID "," TYPE "," SADDR "," SPORT
	"," DADDR "," DPORT "," DIRECTION "," SOCK_INODE ") VALUES(:" EVENT_ID
	",:" TYPE ",:" SADDR ",:" SPORT ",:" DADDR ",:" DPORT ",:" DIRECTION
	",:" SOCK_INODE ");";

char INSERT_LPE_INFO[] =
	"INSERT INTO lpe(" EVENT_ID "," CALLER_RET_ADDR "," TARGET_FUNC
	") VALUES (:" EVENT_ID ",:" CALLER_RET_ADDR ",:" TARGET_FUNC ");";

char INSERT_PTRACE_INFO[] =
	"INSERT INTO ptrace_event(" EVENT_ID "," REQUEST "," ADDR "," TARGET
	") VALUES(:" EVENT_ID ",:" REQUEST ",:" ADDR ",:" TARGET ");";

char INSERT_MODULE_INFO[] = "INSERT INTO module_load(" EVENT_ID "," FILE_ID
			    ") VALUES(:" EVENT_ID ",:" FILE_ID ");";

char INSERT_MODPROBE_OVERWRITE_INFO[] =
	"INSERT INTO modprobe_overwrite_info(" EVENT_ID "," PATH_NAME
	") VALUES(:" EVENT_ID ",:" PATH_NAME ");";

char SELECT_FILE_ID[] = "SELECT * from file_info WHERE " INODE_NUMBER
			" = :" INODE_NUMBER " and " S_MAGIC " = :" S_MAGIC ";";

char SELECT_FILE_ID_PROC_INFO[] =
	"SELECT " FILE_ID " FROM process_info WHERE " EVENT_ID " = :" EVENT_ID
	";";

char SELECT_EVENT_SYSCALL_BY_ID[] =
	"SELECT " SYSCALL " from events WHERE " EVENT_ID " = :" EVENT_ID ";";

char SELECT_SMAGIC_BY_FILE_ID[] =
	"SELECT " S_MAGIC " from file_info WHERE " FILE_ID " = :" FILE_ID ";";

char SELECT_SOCKET_BY_INODE[] =
	"SELECT " EVENT_ID " from socket_create_info WHERE " INODE_NUMBER
	" = :" INODE_NUMBER ";";

char SELECT_FILENAME_BY_FILE_ID[] =
	"SELECT " FILENAME " from file_info WHERE " FILE_ID " = :" FILE_ID ";";

char SELECT_STDOUT_BY_STDIN[] =
	"SELECT " STDIN_INODE ", " EVENT_ID ", " FILE_ID
	" from process_info WHERE " STDOUT_INODE " = :" STDOUT_INODE ";";

char SELECT_STDIN_BY_STDOUT[] =
	"SELECT " STDOUT_INODE ", " EVENT_ID
	" from process_info WHERE " STDIN_INODE " = :" STDIN_INODE ";";

char SELECT_TGID_BY_EVENT_ID[] =
	"SELECT " TGID_PID " from events WHERE " EVENT_ID " = :" EVENT_ID ";";

char SELECT_IF_SOCK_CONN_EXISTS[] =
	"SELECT " EVENT_ID " FROM events WHERE " TGID_PID " = :" TGID_PID
	" and syscall = 41;";

char SELECT_EVENT_IDS_BY_TGID[] =
	"SELECT " EVENT_ID " FROM events where TGID_PID = :" TGID_PID
	" and (syscall = 9 or syscall = 59);";

char SELECT_VM_INFO_BY_EVENT_ID[] =
	"SELECT " VM_BASE ", " VM_LEN ", " VM_PROT
	" FROM proc_mmap WHERE " EVENT_ID " = :" EVENT_ID ";";

char SELECT_COMM_BY_EVENT_ID[] =
	"SELECT " COMM " FROM events WHERE " EVENT_ID " = :" EVENT_ID ";";

char SELECT_COMM[] =
	"SELECT " COMM " FROM disallowed WHERE " COMM " = :" COMM ";";

char BEGIN_STMT[] = "BEGIN;";
char ROLLBACK_STMT[] = "ROLLBACK;";
char COMMIT_STMT[] = "COMMIT;";

typedef struct stmt {
	char *sql;
	const size_t sql_len;
} stmt_t;

const stmt_t SQL_STMTS[] = {
	// Insert Statements
	{ INSERT_EVENT, sizeof(INSERT_EVENT) },
	{ INSERT_FILE_INFO, sizeof(INSERT_FILE_INFO) },
	{ INSERT_PROC_MMAP, sizeof(INSERT_PROC_MMAP) },
	{ INSERT_PROCESS_INFO, sizeof(INSERT_PROCESS_INFO) },
	{ INSERT_TCP_CONN_INFO, sizeof(INSERT_TCP_CONN_INFO) },
	{ INSERT_SOCKET_CREATE_INFO, sizeof(INSERT_SOCKET_CREATE_INFO) },
	{ INSERT_FORK_AND_FRIENDS_INFO, sizeof(INSERT_FORK_AND_FRIENDS_INFO) },
	{ INSERT_LPE_INFO, sizeof(INSERT_LPE_INFO) },
	{ INSERT_PTRACE_INFO, sizeof(INSERT_PTRACE_INFO) },
	{ INSERT_MODULE_INFO, sizeof(INSERT_MODULE_INFO) },
	{ INSERT_MODPROBE_OVERWRITE_INFO,
	  sizeof(INSERT_MODPROBE_OVERWRITE_INFO) },
	// Select statements;
	{ SELECT_FILE_ID, sizeof(SELECT_FILE_ID) },
	{ SELECT_EVENT_SYSCALL_BY_ID, sizeof(SELECT_EVENT_SYSCALL_BY_ID) },
	{ SELECT_FILE_ID_PROC_INFO, sizeof(SELECT_FILE_ID_PROC_INFO) },
	{ SELECT_SMAGIC_BY_FILE_ID, sizeof(SELECT_SMAGIC_BY_FILE_ID) },
	{ SELECT_SOCKET_BY_INODE, sizeof(SELECT_SOCKET_BY_INODE) },
	{ SELECT_FILENAME_BY_FILE_ID, sizeof(SELECT_FILENAME_BY_FILE_ID) },
	{ SELECT_STDOUT_BY_STDIN, sizeof(SELECT_STDOUT_BY_STDIN) },
	{ SELECT_STDIN_BY_STDOUT, sizeof(SELECT_STDIN_BY_STDOUT) },
	{ SELECT_TGID_BY_EVENT_ID, sizeof(SELECT_TGID_BY_EVENT_ID) },
	{ SELECT_IF_SOCK_CONN_EXISTS, sizeof(SELECT_IF_SOCK_CONN_EXISTS) },
	{ SELECT_EVENT_IDS_BY_TGID, sizeof(SELECT_EVENT_IDS_BY_TGID) },
	{ SELECT_VM_INFO_BY_EVENT_ID, sizeof(SELECT_VM_INFO_BY_EVENT_ID) },
	{ SELECT_COMM_BY_EVENT_ID, sizeof(SELECT_COMM_BY_EVENT_ID) },
	{ SELECT_COMM, sizeof(SELECT_COMM) },
	// Misc sql statements
	{ ROLLBACK_STMT, sizeof(ROLLBACK_STMT) },
	{ COMMIT_STMT, sizeof(COMMIT_STMT) },
	{ BEGIN_STMT, sizeof(BEGIN_STMT) }
};

#define NUM_OF_STMTS (sizeof(SQL_STMTS) / sizeof(SQL_STMTS[0]))

#endif // STMTS_H
