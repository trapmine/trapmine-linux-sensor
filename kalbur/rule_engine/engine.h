/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#ifndef ENGINE_H
#define ENGINE_H
#include <safe_hash.h>
#include <message.h>
#include <hash.h>
#include <sqlite3.h>
#include <lua_engine.h>

void process_message(struct message_state *ms, struct lua_engine *e,
		     sqlite3 *db, hashtable_t *ht);

#endif // ENGINE_H
