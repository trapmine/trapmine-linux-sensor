/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file provides the interface for populating the event data into the process context.
 */

#ifndef POPULATE_H
#define POPULATE_H
#include "context_manager.h"

int add_event_context(struct process_context *ctx, struct message_state *ms);

#endif // POPULATE_H
