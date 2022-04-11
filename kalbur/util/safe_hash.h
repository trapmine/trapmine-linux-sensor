/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * The file defines the interface for a threadsafe hashmap
 */

#ifndef SAFEHASH_H
#define SAFEHASH_H

#include "util.h"

safetable_t *init_safetable(void);
void *safe_get(safetable_t *hash_table, unsigned char *key, size_t key_size);
int safe_put(safetable_t *hash_table, unsigned char *key, void *value,
	     size_t key_size);
void *safe_delete(safetable_t *hash_table, unsigned char *key, size_t key_size);
void safe_reset(safetable_t *hash_table);
void delete_safetable(safetable_t *hash_table);

#endif
