/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#ifndef CONSUMER_H
#define CONSUMER_H
#include <pthread.h>
#include <stdbool.h>
#include <safe_hash.h>

#define DB_NAME "/opt/trapmine/db/proc_db"

struct thread_msg {
	pthread_t thread_id;
	pthread_cond_t wakeup;
	pthread_mutex_t mtx;
	bool ready;
	bool die;
	struct msg_list *head;
};

void *consumer(void *arg);

#endif // CONSUMER_H
