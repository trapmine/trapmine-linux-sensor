/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * The file defines the interface for a hashmap
 */

#ifndef HASH_H
#define HASH_H

#include "util.h"

hashtable_t *init_hashtable(void);
void *hash_get(hashtable_t *hash_table, unsigned char *key, size_t key_size);
int hash_put(hashtable_t *hash_table, unsigned char *key, void *value,
	     size_t key_size);
void hash_reset(hashtable_t *hash_table);
void hash_dump(hashtable_t *hash_table);
void delete_table(hashtable_t *hash_table);

#endif
