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

#include <stdio.h>

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

static bool should_process_rules(struct message_state *ms)
{
	if ((!IS_MS_RULES_PROCESSED(ms)) && IS_MS_DB_SAVED(ms)) {
		ASSERT(IS_MS_COMPLETE(ms) != 0,
		       "should_process_rules: ms->progress != completed");
		ASSERT(IS_MS_GC(ms) == 0,
		       "should_process_rules: ms->progress == gc");
		return true;
	}

	return false;
}

void process_message(struct message_state *ms, struct engine *e)
{
	int err;

	ASSERT(e != NULL, "process_message: e == NULL");

	if (should_save_db(ms)) {
		err = save_msg(e->db, e->sqlite_stmts, ms);
		transition_ms_progress(ms, MS_DB_SAVED, err);
	}

	if (should_process_rules(ms)) {
		ASSERT(ms->event_id, "process_message: ms->event_id == 0");
		err = apply_rules(e->le, ms);
		transition_ms_progress(ms, MS_RULES_PROCESSED, err);
	}

#ifdef __DEBUG__
	struct probe_event_header *eh = ms->primary_data;
	if (IS_EXIT_EVENT(eh->syscall_nr)) {
		printf("alert tag: %lu\n", ms->tags[0]);
		printf("hashlookup: %lu\n", ms->tags[1]);
	}
#endif
}
