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
#include <lua_engine.h>
#include <stdlib.h>

#define ASSIGN_WITH_SOFTWARE_BARRIER(lval, rval)                               \
	do {                                                                   \
		lval = rval;                                                   \
		asm volatile("" : : : "memory");                               \
	} while (0)

static int create_db_conn(char *dbname, sqlite3 **database)
{
	return create_connection(dbname, database, 0);
}

static int prepare_thread_run(struct engine **e, pthread_t thread_id)
{
	int err;
	hashtable_t *ht;
	sqlite3 *database;

	ht = init_hashtable();
	if (ht == NULL) {
		fprintf(stderr,
			"prepare_thread_run: failed to allocate space for hash_table\n");
		goto error;
	}

	err = create_db_conn(DB_NAME, &database);
	if (err == CODE_FAILED) {
		fprintf(stderr,
			"prepare_thread_run: failed to create database connection in consumer\n");

		delete_table(ht);
		goto error;
	}

	err = prepare_sql(database, ht);
	if (err == CODE_FAILED) {
		fprintf(stderr,
			"prepare_thread_run: failed to prepare sql statements in consumer\n");

		delete_table(ht);
		sqlite3_close(database);
		goto error;
	}

	*e = (struct engine *)calloc(1UL, sizeof(struct engine));
	if (*e == NULL) {
		fprintf(stderr,
			"prepare_thread_run: failed to allocate memory for engine\n");
		delete_table(ht);
		sqlite3_close(database);
		goto error;
	}
	(*e)->db = database;
	(*e)->sqlite_stmts = ht;

	printf("[%lu] Engine prepared\n", thread_id);

	return CODE_SUCCESS;

error:
	if (*e != NULL) {
		free(*e);
		*e = NULL;
	}
	return CODE_FAILED;
}

static void invoke_engine(struct message_state *ms, struct engine *e)
{
	process_message(ms, e);
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
	struct engine *e = NULL;

	info = (struct thread_msg *)arg;
	ASSERT(info != NULL, "consumer: thread_msg* info == NULL");

	err = prepare_thread_run(&e, info->thread_id);
	if (err == CODE_FAILED)
		goto error;

	ASSERT(e != NULL, "consumer: e == NULL");

	head = info->head;
	ASSERT(head != NULL, "consumer: head == NULL");

	e->le = (struct lua_engine *)info->rule_engine;
	ASSERT(e->le != NULL, "consumer: rule_engine != NULL");

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
					invoke_engine(ms, e);
				}
				pthread_mutex_unlock(&(ms->message_state_lock));
			}
			ms = ms->next_msg;
		}
		pthread_mutex_unlock(&(info->mtx));
	}

	close_database(e->db);

error:
	return NULL;
}
