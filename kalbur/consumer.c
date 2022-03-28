/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * The file contains the code for the worker threads, which
 * receive the completed messages from the message list, and
 * handle them based on their type.
 */

#define _GNU_SOURCE
#include <consumer.h>
#include <stdio.h>
#include <err.h>
#include <message_ls.h>
#include <engine.h>
#include <database.h>
#include <hash.h>

#define ASSIGN_WITH_SOFTWARE_BARRIER(lval, rval)                               \
	do {                                                                   \
		lval = rval;                                                   \
		asm volatile("" : : : "memory");                               \
	} while (0)

static int create_db_conn(char *dbname, sqlite3 **database)
{
	return create_connection(dbname, database, 0);
}

static int prepare_thread_run(hashtable_t **ht, sqlite3 **database,
			      pthread_t thread_id)
{
	int err;

	*ht = init_hashtable();
	if (!(*ht)) {
		fprintf(stderr,
			"prepare_thread_run: failed to allocate space for hash_table\n");
		goto error;
	}

	err = create_db_conn(DB_NAME, database);
	if (err == CODE_FAILED) {
		fprintf(stderr,
			"prepare_thread_run: failed to create database connection in consumer\n");

		delete_table(*ht);
		goto error;
	}

	err = prepare_sql(*database, *ht);
	if (err == CODE_FAILED) {
		fprintf(stderr,
			"prepare_thread_run: failed to prepare sql statements in consumer\n");

		delete_table(*ht);
		sqlite3_close(*database);
		goto error;
	}
	printf("[%lu] Sql prepared\n", thread_id);

	return CODE_SUCCESS;

error:
	*ht = NULL;
	*database = NULL;
	return CODE_FAILED;
}

static void invoke_engine(struct message_state *ms, sqlite3 *db,
			  hashtable_t *ht, safetable_t *table,
			  safetable_t *event_counter)
{
	process_message(ms, db, ht, table, event_counter);
}

static int consume_ms(struct message_state *ms)
{
	return IS_MS_COMPLETE(ms) && (!IS_MS_GC(ms));
}

void *consumer(void *arg)
{
	int err;
	struct message_state *ms;
	struct thread_msg *info;
	struct msg_list *head;
	hashtable_t *hash_table = NULL;
	sqlite3 *db = NULL;

	info = (struct thread_msg *)arg;

	err = prepare_thread_run(&hash_table, &db, info->thread_id);
	if (err == CODE_FAILED)
		goto error;

	head = info->head;

	ASSERT(info != NULL, "consumer: thread_msg* info == NULL");
	ASSERT(head != NULL, "consumer: head == NULL");

	while (true) {
		err = pthread_mutex_lock(&info->mtx);
		ASSERT(err == 0,
		       "consumer: pthread_mutex_lock(info->mtx) != 0");
		while (!info->ready) {
			err = pthread_cond_wait(&(info->wakeup), &(info->mtx));
			ASSERT(err == 0,
			       "consumer: pthread_cond_wait(head->wakeup) != 0");
		}

		if (info->die)
			goto error;

		info->ready = false;

		// ms should be assigned after lock is acquired
		// thus the software barrier to force instruction
		// ordering.
		ASSIGN_WITH_SOFTWARE_BARRIER(ms, head->first);
		while (ms != NULL) {
			if (pthread_mutex_trylock(&(ms->message_state_lock)) ==
			    0) {
				if (consume_ms(ms)) {
					invoke_engine(ms, db, hash_table,
						      info->safe_hashtable,
						      info->event_counter);
					//	err = save_msg(db, hash_table, ms);
					//	if (err == CODE_SUCCESS) {
					//		set_saved(ms);
					//	} else if (err == CODE_FAILED)
					//		set_discard(ms);
				}
				pthread_mutex_unlock(&(ms->message_state_lock));
			}
			ms = ms->next_msg;
		}
		pthread_mutex_unlock(&(info->mtx));
	}

	close_database(db);

error:
	return NULL;
}
