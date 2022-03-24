/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#ifndef ERR_H
#define ERR_H

#ifdef APPLY_ASSERT
#include <assert.h>
#define ASSERT(expr, msg) assert(expr &&msg)
#else
#define ASSERT(expr, msg)                                                      \
	do {                                                                   \
	} while (0)
#endif

#define CODE_FAILED -1
#define CODE_SUCCESS 1
#define CODE_RETRY -2

#define ERR_NOT_SUCCESS(err) ((err == CODE_FAILED) || (err == CODE_RETRY))

#define MAX_ERRNO (4095UL)

#endif // ERR_H
