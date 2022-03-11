/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file contains the code for performing lookups for kernel symbols.
 * The kernel symbols and their associated addresses are read from
 * /proc/kallsyms, and saved in memory. The file provides functions for finding
 * symbol address given the name, or symbol name, given the address.
 */

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include "symsearch.h"

#define COMMIT_CREDS_PARENTS "/opt/trapmine/data/commit_creds.parents"
#define MAX_SYMS 300000
#define MAX_PARENTS 100

struct ksym {
	unsigned long addr;
	char *name;
};

static unsigned long commit_creds_pls[MAX_PARENTS];
static struct ksym syms[MAX_SYMS];
static int sym_cnt;

int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char func[256], buf[256];
	char symbol;
	void *addr;
	int i = 0;

	if (!f)
		return -ENOENT;

	while (fgets(buf, 256, f)) {
		if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
			break;
		if (!addr)
			continue;
		syms[i].addr = (unsigned long)addr;
		syms[i].name = strdup(func);
		i++;
	}
	fclose(f);
	sym_cnt = i;
	return 0;
}

unsigned long ksym_get_addr(char *name)
{
	int i;

	for (i = 0; i < sym_cnt; i++) {
		if (strcmp(syms[i].name, name) == 0)
			return syms[i].addr;
	}

	return 0;
}

static unsigned long find_function_addr(unsigned long addr)
{
	unsigned long func_addr = 0;

	for (int i = 0; i < sym_cnt; ++i) {
		if (syms[i].addr > addr)
			continue;

		if ((addr - syms[i].addr) < (addr - func_addr)) {
			func_addr = syms[i].addr;
		}
	}

	return func_addr;
}

unsigned long is_commit_creds_parent(unsigned long addr)
{
	unsigned long func;
	func = find_function_addr(addr);

	for (int i = 0; i < MAX_PARENTS; ++i) {
		if (commit_creds_pls[i] == func)
			return func;
	}

	return 0;
}

int build_commit_creds_pls()
{
	FILE *f = fopen(COMMIT_CREDS_PARENTS, "r");
	if (f == NULL) {
		fprintf(stderr, "Failed to open %s: %d\n", COMMIT_CREDS_PARENTS, errno);
		return 0;
	}
	unsigned long addr;

	char func[256], buf[256];
	size_t counter = 0;

	if (!f)
		return -ENOENT;

	while (fgets(buf, 256, f)) {
		if (sscanf(buf, "%s", func) != 1)
			break;

		if (counter > MAX_PARENTS) {
			fprintf(stderr,
				"Parent list size exceeded size of buffer\n");
			break;
		}

		addr = ksym_get_addr(func);
		commit_creds_pls[counter] = addr;
		counter++;
	}

	fclose(f);
	return 0;
}
