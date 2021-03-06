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

char *build_cmdline(char *args_data, uint32_t argv_off, unsigned long nbytes)
{
	char *args = NULL;
	char *str = NULL;

	ASSERT(argv_off != LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE),
	       "build_env: env_off == LAST_NULL_BYTE");

	if (args_data[argv_off] == 0)
		return NULL;

	args = calloc(nbytes, sizeof(char));
	if (args == NULL)
		return NULL;

	str = &(args_data[argv_off]);
	memcpy(args, str, nbytes);
	for (unsigned int i = 0; i < nbytes; ++i) {
		if (args[i] == 0)
			args[i] = ',';
	}

	return args;
}

char *build_env(char *env_data, uint32_t env_off, unsigned long nbytes)
{
	char *env = NULL;
	char *str = NULL;

	ASSERT(env_off != LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE),
	       "build_env: env_off == LAST_NULL_BYTE");

	if (env_data[env_off] == 0)
		return NULL;

	env = calloc(nbytes, sizeof(char));
	if (env == NULL)
		return NULL;

	str = &(env_data[env_off]);
	memcpy(env, str, nbytes);

	for (unsigned int i = 0; i < nbytes; ++i) {
		if (env[i] == 0)
			env[i] = ',';
	}
	return env;
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

