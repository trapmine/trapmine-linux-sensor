/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file contains the code for driving the rule engine
 */

#include <engine.h>
#include <populate.h>
#include <context_manager.h>
#include <stdbool.h>
#include <save_ms.h>
#include <err.h>

static bool should_manage_ctx(struct message_state *ms)
{
	ASSERT(IS_MS_COMPLETE(ms) != 0,
	       "should_manage_ctx: ms->progress != completed");
	ASSERT(IS_MS_GC(ms) == 0, "should_save_db: ms->progress == gc");

	if (!(IS_MS_CTX_SAVED(ms) || IS_MS_IGNORE_CTX_SAVE(ms))) {
		return true;
	}

	return false;
}

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
		     hashtable_t *sqlite_stmts, safetable_t *table,
		     safetable_t *event_counter)
{
	int err;

	if (should_manage_ctx(ms)) {
		err = manage_process_context(table, event_counter, ms);
		transition_ms_progress(ms, MS_CTX_SAVED, err);
	}

	if (should_save_db(ms)) {
		err = save_msg(db, sqlite_stmts, ms);
		transition_ms_progress(ms, MS_DB_SAVED, err);
	}
}
