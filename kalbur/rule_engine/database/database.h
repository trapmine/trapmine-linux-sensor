/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * The file defines the interface for interacting with the database.
 */

#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <events.h>
#include <message.h>
#include "util.h"

#define TIMEOUT_MS 1000

int create_connection(char *dbname, sqlite3 **db, int inmem);
int initialize_database(char *dbname);
int prepare_sql(sqlite3 *db, hashtable_t *ht);
int insert_event(sqlite3 *db, hashtable_t *ht, struct probe_event_header *eh);
int insert_file_info(sqlite3 *db, hashtable_t *ht, char *string_data,
		     struct file_info *f);
int insert_proc_info(sqlite3 *db, hashtable_t *ht, struct message_state *ms,
		     int event_id, int file_id);
int insert_mmap_info(sqlite3 *db, hashtable_t *ht, struct proc_mmap *pm,
		     int event_id, int file_id);
int insert_socket_create_info(sqlite3 *db, hashtable_t *ht,
			      struct message_state *ms, int event_id);
int insert_tcp_conn_info(sqlite3 *db, hashtable_t *ht, struct message_state *ms,
			 int event_id);
int insert_fork_and_friends_event(sqlite3 *db, hashtable_t *ht,
				  struct message_state *ms, int event_id);
int insert_lpe_info(sqlite3 *db, hashtable_t *ht, struct message_state *ms,
		    int event_id);
int insert_ptrace_event(sqlite3 *db, hashtable_t *ht, struct message_state *ms,
			int event_id);
int insert_kernel_module_info(sqlite3 *db, hashtable_t *ht, int file_id,
			      int event_id);
int insert_modprobe_overwrite_info(sqlite3 *db, hashtable_t *ht,
				   struct message_state *ms, int event_id);
int rollback_transaction(sqlite3 *db, hashtable_t *ht);
int commit_transaction(sqlite3 *db, hashtable_t *ht);
int begin_transaction(sqlite3 *db, hashtable_t *ht);
void close_database(sqlite3 *db);
#endif // DATABASE_H
