/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#ifndef SAVE_MS_H
#define SAVE_MS_H

int save_msg(sqlite3 *db, hashtable_t *hash_table, struct message_state *ms);

#endif // SAVE_MS_H
