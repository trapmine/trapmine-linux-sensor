/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#ifndef HELPER_DEFS_H
#define HELPER_DEFS_H

#define STRINGIFY(x) #x

#define PARAM_HOLDER(param) ":" param

/* Disable the following warnings for this macro.
 * We want to pass unsigned types for int and int64, which
 * sqlite3 does not provide prototypes for. */

#define SQLITE3_BIND_INT(caller, type, param, val)                             \
	_Pragma(STRINGIFY(GCC diagnostic push)) _Pragma(                       \
		STRINGIFY(GCC diagnostic ignored "-Wtraditional-conversion"))  \
		_Pragma(STRINGIFY(GCC diagnostic ignored                       \
				  "-Wsign-conversion")) do                     \
	{                                                                      \
		err = sqlite3_bind_##type(                                     \
			ppStmt,                                                \
			sqlite3_bind_parameter_index(ppStmt, ":" param), val); \
		if (err != SQLITE_OK) {                                        \
			fprintf(stderr,                                        \
				caller                                         \
				": Failed to bind to %s with %ld: %s\n",       \
				param, (long)val, sqlite3_errmsg(db));         \
			return CODE_RETRY;                                     \
		}                                                              \
	}                                                                      \
	while (0)                                                              \
		;                                                              \
	_Pragma(STRINGIFY(GCC diagnostic pop))

#define SQLITE3_BIND_STR(caller, type, param, val)                             \
	do {                                                                   \
		err = sqlite3_bind_##type(                                     \
			ppStmt,                                                \
			sqlite3_bind_parameter_index(ppStmt, ":" param), val,  \
			-1, SQLITE_STATIC);                                    \
		if (err != SQLITE_OK) {                                        \
			fprintf(stderr,                                        \
				caller ": Failed to bind to %s with %s: %s\n", \
				param, val, sqlite3_errmsg(db));               \
			return CODE_RETRY;                                     \
		}                                                              \
	} while (0)

#define SQLITE3_GET(dest, type, index)                                         \
	_Pragma(STRINGIFY(GCC diagnostic push)) _Pragma(                       \
		STRINGIFY(GCC diagnostic ignored "-Wtraditional-conversion"))  \
		_Pragma(STRINGIFY(GCC diagnostic ignored "-Wsign-conversion")) \
			dest = sqlite3_column_##type(ppStmt, index);           \
	_Pragma(STRINGIFY(GCC diagnostic pop))

#endif // HELPER_DEFS_H
