/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * The file contains the code for a simple thread safe hashmap.
 * It uses the implementation of the hashmap from hash.c along
 * with a mutex.
 */

#include <hash.h>
#include <safe_hash.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

safetable_t *init_safetable(void)
{
	safetable_t *table;
	int err;

	table = calloc(1UL, sizeof(safetable_t));
	if (table == NULL) {
		return NULL;
	}

	err = pthread_mutex_init(&table->lock, NULL);
	if (err != 0) {
		free(table);
		return NULL;
	}

	table->ht = init_hashtable();
	if (table->ht == NULL) {
		free(table);
		return NULL;
	}

	return table;
}

void *safe_get(safetable_t *table, unsigned char *key, size_t key_size)
{
	int err;
	void *res;

	err = pthread_mutex_lock(&table->lock);
	if (err != 0) {
		fprintf(stderr,
			"safe_get: Error while trying to acquire lock on table: %d\n",
			errno);
		return NULL;
	}

	res = hash_get(table->ht, key, key_size);

	pthread_mutex_unlock(&table->lock);

	return res;
}

int safe_put(safetable_t *table, unsigned char *key, void *value,
	     size_t key_size)
{
	int err;

	err = pthread_mutex_lock(&table->lock);
	if (err != 0) {
		fprintf(stderr,
			"safe_put: Error while trying to acquire lock on table: %d\n",
			errno);
		return CODE_FAILED;
	}

	err = hash_put(table->ht, key, value, key_size);

	pthread_mutex_unlock(&table->lock);

	return err;
}

void *safe_delete(safetable_t *table, unsigned char *key, size_t key_size)
{
	int err;
	void *val;

	err = pthread_mutex_lock(&table->lock);
	if (err != 0) {
		fprintf(stderr,
			"safe_delete: Error while trying to acquire lock on table: %d\n",
			err);
		return NULL;
	}

	val = hash_delete(table->ht, key, key_size);
	pthread_mutex_unlock(&table->lock);

	return val;
}

void safe_reset(safetable_t *table)
{
	int err;

	err = pthread_mutex_lock(&table->lock);
	if (err != 0) {
		fprintf(stderr,
			"safe_reset: Error while trying to acquire lock on table: %d\n",
			errno);
		return;
	}

	hash_reset(table->ht);

	pthread_mutex_unlock(&table->lock);

	return;
}

void delete_safetable(safetable_t *table)
{
	int err;

	err = pthread_mutex_lock(&table->lock);
	if (err != 0) {
		fprintf(stderr,
			"delete_safetable: Error while trying to acquire lock on table: %d\n",
			errno);
		return;
	}

	delete_table(table->ht);

	pthread_mutex_unlock(&table->lock);

	pthread_mutex_destroy(&table->lock);
	free(table);

	return;
}

