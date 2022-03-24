#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include "helpers.h"

static size_t calc_path_sz(char **parts, uint32_t pathlen)
{
	size_t sz = 0;

	for (uint32_t i = 0; i < pathlen; ++i) {
		sz += strlen(parts[i]);
	}

	// We also have pathlen-1 '/'s + trailing nullbyte + buffer space
	return sz + (pathlen * 2);
}

char *build_cmdline(char *args_data, uint32_t argv_off, uint32_t nargv)
{
	uint32_t cnt, indx;
	size_t arg_sz;
	char *args = NULL;
	char *dest = NULL;
	char *str = NULL;

	for (indx = argv_off, cnt = 0; cnt < nargv; indx++) {
		if (indx >= PER_CPU_STR_BUFFSIZE) {
			ASSERT(indx < PER_CPU_STR_BUFFSIZE,
			       "build_args_str: indx >= PER_CPU_STR_BUFFSIZE");
			return NULL;
		}
		if (args_data[indx] == 0)
			cnt++;
	}

	arg_sz = indx - argv_off;
	args = calloc(arg_sz, sizeof(char));
	if (args != NULL) {
		dest = args;
		str = &(args_data[argv_off]);
		for (uint32_t i = 0; i < nargv; ++i) {
			args = strcat(args, str);
			dest = strchr(args, '\0');
			*dest = ',';
			str = strchr(str, '\0');
			str++;
		}

		return args;
	} else {
		return NULL;
	}
}
char *build_filename_from_event(char *file_path, uint32_t pathlen)
{
	char **parts;
	int marker;
	char *filename;
	char *dest;
	size_t src_len, path_sz;

	parts = (char **)malloc(pathlen * sizeof(char *));
	if (parts == NULL)
		goto out;

	marker = 0;
	for (int i = (int)pathlen - 1; i >= 0; i--) {
		parts[i] = (char *)&file_path[marker];
		while (file_path[marker] != 0)
			marker++;

		marker++;
	}

	path_sz = calc_path_sz(parts, pathlen);

	filename = (char *)calloc(sizeof(char), path_sz);
	if (filename == NULL) {
		fprintf(stderr, "build_file_name: malloc failed\n");
		goto out;
	}

	dest = filename;
	if (pathlen > 1) {
		*dest = '/';
		dest++;
	}
	for (uint32_t i = 0; i < pathlen; ++i) {
		src_len = strlen(parts[i]);
		dest = memcpy(dest, parts[i], src_len);
		dest = dest + src_len;
		*dest = '/';
		dest++;
	}
	dest = dest - sizeof(char);
	*dest = 0;

out:
	if (parts != NULL)
		free(parts);
	return filename;
}

