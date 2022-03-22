/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * The file contains the code for a simple hashmap implementation.
 * The code assumes a fixed length hashmap, where the length is the
 * number of buckets in the hashmap.
 * It uses the crc23c hash function to map a key into a bucket.
 */

#include "hash.h"
#include "crc32c_tbl.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>

#define CALL(macro, ...) macro(__VA_ARGS__)
#define TYPED(value, type) value##type
#define TYPED_MACRO(value, type) CALL(TYPED, value, type)

#define CRC_INIT 0xFFFFFFFF
#define KEY_PTR(hash_table) (&(hash_table[index]->key))

static uint32_t crc32c_hash(const void *buf, size_t size)
{
	const uint8_t *p = buf;
	uint32_t crc;

	crc = CRC_INIT;
	while (size--)
		crc = crc32Table[(crc ^ *p++) & 0xff] ^ (crc >> 8);

	return crc;
}

static inline unsigned int key_index(uint32_t hash)
{
	return hash % MAX_HASH_ENTRIES;
}

static unsigned int cmp_keys(struct key_struct *k1, struct key_struct *k2)
{
	return k1->key_hash == k2->key_hash;
}

static struct entry *find_entry(hashtable_t *hash_table,
				const unsigned int index,
				struct key_struct *key)
{
	struct entry *e;

	if (hash_table[index] == NULL)
		return NULL;

	if (cmp_keys(KEY_PTR(hash_table), key))
		return hash_table[index];

	for (e = hash_table[index]->next; e; e = e->next)
		if (cmp_keys(&(e->key), key))
			return e;
	return NULL;
}

static int construct_new_elem(struct entry **elem, void *value,
			      struct key_struct *ks)
{
	struct entry *new_elem;

	new_elem = malloc(sizeof(struct entry));
	if (!new_elem) {
		fprintf(stderr, "Failed to malloc new entry for hashmap\n");
		return CODE_FAILED;
	}

	new_elem->key.key_hash = ks->key_hash;
	new_elem->key.key = ks->key;
	new_elem->value = value;
	new_elem->next = NULL;
	*elem = new_elem;

	return CODE_SUCCESS;
}

static int insert_hash_table(hashtable_t *hash_table, const unsigned int index,
			     void *value, struct key_struct *ks)
{
	struct entry *e, *prev;
	int err;

	if (hash_table[index] == NULL) {
		err = construct_new_elem(&hash_table[index], value, ks);
		return err;
	}

	if (cmp_keys(KEY_PTR(hash_table), ks)) {
		hash_table[index]->value = value;
		return CODE_SUCCESS;
	}

	prev = hash_table[index];
	for (e = prev->next; e; e = e->next) {
		if (cmp_keys(&(e->key), ks)) {
			e->value = value;
			return CODE_SUCCESS;
		}
		prev = e;
	}

	err = construct_new_elem(&(prev->next), value, ks);
	return err;
}

hashtable_t *init_hashtable(void)
{
	return calloc(TYPED_MACRO(MAX_HASH_ENTRIES, UL),
		      sizeof(struct entry *));
}

void *hash_get(hashtable_t *hash_table, unsigned char *key, size_t data_size)
{
	struct entry *e;
	struct key_struct ks;

	ks.key_hash = crc32c_hash(key, data_size);
	ks.key = key;

	unsigned int index = key_index(ks.key_hash);

	e = find_entry(hash_table, index, &ks);
	if (e == NULL) {
		return NULL;
	}

	return e->value;
}

int hash_put(hashtable_t *hash_table, unsigned char *key, void *value,
	     size_t data_size)
{
	struct entry *e;

	struct key_struct ks;
	ks.key_hash = crc32c_hash(key, data_size);
	ks.key = key;

	unsigned int index = key_index(ks.key_hash);

	e = find_entry(hash_table, index, &ks);
	if (e != NULL) {
		e->value = value;
		return CODE_SUCCESS;
	}

	return insert_hash_table(hash_table, index, value, &ks);
}

void hash_reset(hashtable_t *hash_table)
{
	struct entry *e, *tmp;

	for (unsigned int bkt = 0; bkt < MAX_HASH_ENTRIES; ++bkt) {
		e = hash_table[bkt];
		while (e) {
			tmp = e;
			e = e->next;
			free(tmp);
		}
	}
	memset(hash_table, 0, TYPED_MACRO(MAX_HASH_ENTRIES, UL));
}

void delete_table(hashtable_t *ht)
{
	hash_reset(ht);
	free(ht);
}
