/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#ifndef ENUM_STR_H
#define ENUM_STR_H

// Used to convert state numbers to names for database
const char *TCP_STATE_NAMES[] = { "UNDEF",    "ESTABLISHED", "SYN_SENT",
				  "SYN_RECV", "FIN_WAIT1",   "TIME_WAIT",
				  "CLOSE",    "CLOSE_WAIT",  "LAST_ACK",
				  "LISTEN",   "CLOSING",     "NEW_SYN_RECV" };

#endif
