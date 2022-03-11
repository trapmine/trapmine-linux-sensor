/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file defines the interface for a lookup table for kernel symbols
 */

#ifndef SYMSEARCH_H
#define SYMSEARCH_H

int load_kallsyms(void);
unsigned long ksym_get_addr(char *name);
unsigned long is_commit_creds_parent(unsigned long addr);
int build_commit_creds_pls(void);

#endif
