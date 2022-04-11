/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * The linux sensor project uses sqlite3 as a rule engine.
 * This file contains the schema for the database used.
 */

#ifndef SCHEMA_H
#define SCHEMA_H

#define UINT64_T UNSIGNED BIG INT
#define INT64_T BIT INT

// ###########################
// #### TABLE DEFINITIONS ####
// ###########################

/* events metadata table */

// Columns
#define EVENT_TIME "event_time"
#define TGID_PID "tgid_pid"
#define SYSCALL "syscall"
#define COMM "process_name"
#define EVENT_ID "event_id" // alias for rowid

// Table definition
#define EVENTS_TABLE                                                           \
	"CREATE TABLE events( \
				" EVENT_ID " INTEGER PRIMARY KEY, \
				" EVENT_TIME " UINT64_T NOT NULL, \
				" TGID_PID " UINT64_T NOT NULL, \
				" SYSCALL " INTEGER NOT NULL, \
				" COMM " TEXT \
		      	);"

/* file information table */

//Columns
#define FILENAME "filename"
#define INODE_NUMBER "inode_number"
#define S_MAGIC "s_magic"
#define FILE_ID "file_id" // alias for rowid

// Table definition
#define FILE_INFO_TABLE                                                        \
	"CREATE TABLE file_info( \
				" FILE_ID " INTEGER PRIMARY KEY, \
				" FILENAME " TEXT, \
				" INODE_NUMBER " UINT64_T NOT NULL, \
				" S_MAGIC " UINT64_T NOT NULL \
			 );"

/* Memory map info table */

// Columns
#define VM_BASE "vm_base"
#define VM_FLAGS "vm_flags"
#define VM_PROT "vm_prot"
#define VM_LEN "vm_len"

// Table definition
#define PROCESS_MMAP_TABLE                                                     \
	"CREATE TABLE proc_mmap( \
				" EVENT_ID " INTEGER, \
				" VM_BASE " UINT64_T, \
				" VM_FLAGS " UINT64_T NOT NULL, \
				" VM_PROT " UINT64_T NOT NULL, \
				" VM_LEN " UINT64_T NOT NULL, \
				" FILE_ID " INTEGER , \
				PRIMARY KEY(" EVENT_ID "," VM_BASE "), \
				FOREIGN KEY(" EVENT_ID                         \
	") REFERENCES events(" EVENT_ID "), \
				FOREIGN KEY(" FILE_ID                          \
	") REFERENCES file_info(" FILE_ID ") \
			 );"
/* Process info table */

// Columns
#define PPID "ppid"
#define ARGS "args"
#define INTERPRETER "interpreter"
#define UID "uid"
#define GID "gid"
#define EUID "euid"
#define EGID "egid"
#define STDIN_INODE "stdin_inode"
#define STDIN_TYPE "stdin_type"
#define STDOUT_INODE "stdout_inode"
#define STDOUT_TYPE "stdout_type"
#define STDERR_INODE "stderr_inode"
#define STDERR_TYPE "stderr_type"
#define ENV "environment"
#define CLONE_FLAGS "clone_flags"

#define PROCESS_INFO_TABLE                                                     \
	"CREATE TABLE process_info(						\
		" EVENT_ID                                                     \
	" INTEGER PRIMARY KEY, 				\
		" PPID                                                         \
	" UINT64_T,						\
		" CLONE_FLAGS                                                  \
	" UINT64_T, 					\
		" FILE_ID                                                      \
	" INTEGER NOT NULL, 					\
		" ARGS                                                         \
	" TEXT, 							\
		" ENV                                                          \
	" TEXT, 							\
		" INTERPRETER                                                  \
	" TEXT, 						\
		" UID                                                          \
	" INTEGER, 						\
		" GID                                                          \
	" INTEGER, 						\
		" EUID                                                         \
	" INTEGER, 						\
		" EGID                                                         \
	" INTEGER, 						\
		" STDIN_INODE                                                  \
	" INTEGER,					\
		" STDIN_TYPE                                                   \
	" INTEGER,						\
		" STDOUT_INODE                                                 \
	" INTEGER,					\
		" STDOUT_TYPE                                                  \
	" INTEGER,					\
		" STDERR_INODE                                                 \
	" INTEGER,					\
		" STDERR_TYPE                                                  \
	" INTEGER,					\
		FOREIGN KEY(" EVENT_ID ") REFERENCES events(" EVENT_ID         \
	"), 	\
		FOREIGN KEY(" FILE_ID ") REFERENCES file_info(" FILE_ID        \
	")	\
	);"

/* Socket create info table */
#define FAMILY "family"
#define SOCK_TYPE "type"

#define SOCKET_CREATE_TABLE                                                    \
	"CREATE TABLE socket_create_info(\
				" EVENT_ID " INTEGER PRIMARY KEY,\
				" INODE_NUMBER " UINT64_T,\
				" FAMILY " TEXT,\
				" SOCK_TYPE " TEXT,\
				FOREIGN KEY(" EVENT_ID                         \
	") REFERENCES events(" EVENT_ID ")\
				);"

/* Socket connection info table */
#define TYPE "inet_type"
#define SADDR "local_address"
#define SPORT "local_port"
#define DADDR "remote_address"
#define DPORT "remote_port"
#define DIRECTION "direction"
#define SOCK_INODE "socket_inode"

#define TCP_CONNECTION_TABLE                                                   \
	"CREATE TABLE tcp_connection_info(\
				" EVENT_ID " INTEGER PRIMARY KEY, \
				" TYPE " TEXT NOT NULL, \
				" SADDR " TEXT, \
				" SPORT " INTEGER, \
				" DADDR " TEXT, \
				" DPORT " INTEGER, \
				" DIRECTION " TEXT, \
				" SOCK_INODE ", INTEGER \
			);"

/* LPE alert table */
#define CALLER_RET_ADDR "caller_ret_addr"
#define TARGET_FUNC "target_func"
#define LPE_TABLE                                                              \
	"CREATE TABLE lpe(\
			" EVENT_ID " INTEGER PRIMARY KEY, \
			" CALLER_RET_ADDR " UINT64_T,\
			" TARGET_FUNC " TEXT,\
			FOREIGN KEY(" EVENT_ID ") REFERENCES events(" EVENT_ID \
	")\
			);"

/* ptrace event table */
#define REQUEST "request"
#define ADDR "address"
#define TARGET "target_tgid_pid"

#define PTRACE_TABLE                                                           \
	"CREATE table ptrace_event(\
			" EVENT_ID " INTEGER PRIMARY KEY, \
			" REQUEST " UINT64_T,\
			" ADDR " UINT64_T,\
			" TARGET " UINT64_T,\
			FOREIGN KEY(" EVENT_ID ") REFERENCES events(" EVENT_ID \
	")\
			);"

/* Disallowed parents for shell */
#define DISALLOWED_TABLE                                                       \
	"CREATE table disallowed(\
				" COMM " TEXT NOT NULL\
			);"

/* Kernel module load */
#define KERNEL_MODULE_LOAD_TABLE                                               \
	"CREATE TABLE module_load(\
				" EVENT_ID " INTEGER PRIMARY KEY, \
				" FILE_ID " INTEGER, \
				FOREIGN KEY(" EVENT_ID                         \
	") REFERENCES events(" EVENT_ID "),\
				FOREIGN KEY(" FILE_ID                          \
	") REFERENCES file_info(" FILE_ID ")\
				);"

/* Modprobe overwrite info */
#define PATH_NAME "new_modprobe_path"
#define MODPROBE_OVERWRITE_TABLE                                               \
	"CREATE TABLE modprobe_overwrite_info(\
				" EVENT_ID " INTEGER PRIMARY KEY, \
				" PATH_NAME " TEXT,\
				FOREIGN KEY(" EVENT_ID                         \
	") REFERENCES events(" EVENT_ID ") \
				);"

#endif // SCHEMA_H
