/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file contains the code for driving the rule engine
 */

#include <engine.h>
#include <stdbool.h>
#include <save_ms.h>
#include <err.h>

static bool should_save_db(struct message_state *ms)
{
	if (!(IS_MS_DB_SAVED(ms))) {
		ASSERT(IS_MS_COMPLETE(ms) != 0,
		       "should_save_db: ms->progress != completed");
		ASSERT(IS_MS_GC(ms) == 0, "should_save_db: ms->progress == gc");

		return true;
	}

	return false;
}

void process_message(struct message_state *ms, sqlite3 *db,
		     hashtable_t *sqlite_stmts)
{
	int err;

	if (should_save_db(ms)) {
		err = save_msg(db, sqlite_stmts, ms);
		transition_ms_progress(ms, MS_DB_SAVED, err);
	}
}
