/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#define MAX_HASH_ENTRIES 200

struct key_struct {
	uint32_t key_hash;
	unsigned char *key;
};

struct entry {
	struct key_struct key;
	void *value;
	struct entry *next;
};

typedef struct entry *hashtable_t;

typedef struct {
	hashtable_t *ht;
	pthread_mutex_t lock;
} safetable_t;

#endif // UTIL_H
