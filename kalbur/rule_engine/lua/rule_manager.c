#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <err.h>
#include "rule_manager.h"

#define LUA_EXT ".lua"
#define RULES_DIR "/opt/trapmine/rules"

static int load_lua_chunk(lua_State *L, char *script, struct stat *statbuff)
{
	ASSERT(script != NULL, "load_lua: script == NULL");
	char *script_data;
	int fd, err;
	unsigned long buff_sz;

	fd = open(script, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr,
			"load_lua_chunk: Failed to open file: %s: %d: %s\n",
			script, errno, strerror(errno));
		return CODE_FAILED;
	}

	buff_sz = statbuff->st_size * sizeof(char);
	script_data = (char *)malloc(buff_sz);
	if (script_data == NULL) {
		fprintf(stderr,
			"load_lua_chunk: Failed to allocate memory for reading lua script\n");
		return CODE_FAILED;
	}

	err = read(fd, script_data, buff_sz);
	if (err == -1) {
		fprintf(stderr,
			"load_lua_chunk: Failed to read file %s: %d: %s\n",
			script, errno, strerror(errno));
		return CODE_FAILED;
	}
	if (err < statbuff->st_size) {
		fprintf(stderr,
			"load_lua_chunk: Failed to read all bytes: %ld. Bytes read: %d\n",
			statbuff->st_size, err);
		return CODE_FAILED;
	}

	err = luaL_loadbuffer(L, script_data, buff_sz, script);
	if (err != LUA_OK) {
		ASSERT(lua_isstring(L, -1), "");
		char *errstr = lua_tostring(L, -1);
		fprintf(stderr,
			"load_lua_chunk: Failed to load lua chunk: %d: %s\n",
			err, errstr);

		return CODE_FAILED;
	}

	return CODE_SUCCESS;
}

#define PTR_ARITHMETIC(ptr, ptr_type_cast, add)                                \
	({                                                                     \
		unsigned long __ptr = (unsigned long)ptr;                      \
		__ptr = __ptr + add;                                           \
		(ptr_type_cast) __ptr;                                         \
	})

static int write_lua_chunk(lua_State *L, const void *p, size_t sz, void *ud)
{
	char *new, *addpoint;

	struct rule_list *r = (struct rule_list *)ud;

	new = (char *)realloc(r->rule_bytecode, r->bytecode_sz + sz);
	if (new == NULL)
		return 1;

	addpoint = PTR_ARITHMETIC(new, char *, r->bytecode_sz);
	memcpy(addpoint, p, sz);
	r->rule_bytecode = new;
	r->bytecode_sz += sz;

	return 0;
}

static struct rule_list *new_rule(struct rule_list **event_rls, int event_indx,
				  char *filename, size_t namesz)
{
	struct rule_list *tmp;

	struct rule_list *r =
		(struct rule_list *)calloc(1UL, sizeof(struct rule_list));
	if (r == NULL)
		return NULL;

	r->script_name = (char *)calloc(namesz, sizeof(char));
	if (r->script_name == NULL) {
		free(r);
		return NULL;
	}
	memcpy(r->script_name, filename, namesz);

	tmp = event_rls[event_indx];
	if (tmp == NULL) {
		event_rls[event_indx] = r;
		return r;
	}

	while (tmp->next_rule != NULL) {
		tmp = tmp->next_rule;
	}
	tmp->next_rule = r;

	return r;
}

static int dump_lua_chunk(lua_State *L, off_t size,
			  struct rule_list **event_rls, int event_indx,
			  char *filename)
{
	int err;
	struct rule_list *nr;

	nr = new_rule(event_rls, event_indx, filename, 256);
	if (nr == NULL)
		return CODE_FAILED;

	err = lua_dump(L, write_lua_chunk, nr, 0);
	if (err != 0)
		return CODE_FAILED;

	return CODE_SUCCESS;
}

static void free_rule_list(struct rule_list *r)
{
	struct rule_list *tmp;
	while (r != NULL) {
		tmp = r;
		r = r->next_rule;
		free(tmp->rule_bytecode);
		free(r->script_name);
		free(tmp);
	}
}

void free_rules_manager(struct rules_manager *manager)
{
	ASSERT(manager != NULL, "free_rules_manager: manager == NULL");
	ASSERT(manager->event_rls != NULL,
	       "free_rules_manager: event_rls == NULL");

	struct rule_list **rls;
	rls = manager->event_rls;

	for (unsigned int i = 0; i < manager->rls_sz; i++) {
		if (rls[i] != NULL) {
			free_rule_list(rls[i]);
			rls[i] = NULL;
		}
	}

	free(manager);
}

struct rules_manager *new_rules_manager(size_t rls_sz)
{
	struct rules_manager *new;

	new = (struct rules_manager *)calloc(1UL, sizeof(struct rules_manager));
	if (new == NULL)
		return NULL;

	new->event_rls = calloc(rls_sz, sizeof(struct rule_list *));
	if (new->event_rls == NULL) {
		free(new);
		return NULL;
	}

	new->rules_loaded = 0;
	new->rls_sz = rls_sz;

	return new;
}

int load_lua_scripts(lua_State *L, struct rules_manager *manager)
{
	ASSERT(L != NULL, "load_lua_scripts: L == NULL");
	ASSERT(manager != NULL, "load_lua_scripts: manager == NULL");

	int err;
	struct stat statbuff;
	struct dirent *entry;
	char _lua_file[256];
	DIR *rules_dir;
	struct rule_list **event_rls;

	rules_dir = opendir(RULES_DIR);
	if (rules_dir == NULL) {
		fprintf(stderr, "load_lua_scripts: Failed to open %s: %d: %s\n",
			RULES_DIR, errno, strerror(errno));

		return CODE_FAILED;
	}

	event_rls = manager->event_rls;
	ASSERT(event_rls != NULL, "load_lua_scripts: event_rls == NULL");
	while ((entry = readdir(rules_dir)) != NULL) {
		if (entry->d_type != DT_REG)
			continue;

		ASSERT(entry->d_name != NULL,
		       "load_lua_scripts: d_name == NULL");
		if (strstr(entry->d_name, LUA_EXT) == NULL)
			continue;

		snprintf(_lua_file, 256, "%s/%s", RULES_DIR, entry->d_name);

		err = stat(_lua_file, &statbuff);
		// This might fail in case the filename is longer than 256
		// character. For now we can just ignore the error and go to next file
		// TODO: account for the case where filename is greater than 256
		if (err == -1) {
			continue;
		}

		err = load_lua_chunk(L, _lua_file, &statbuff);
		if (err != CODE_SUCCESS) {
			fprintf(stderr,
				"load_lua_scripts: Could not load lua file into buffer: %s\n",
				_lua_file);
			continue;
		}

		err = dump_lua_chunk(L, statbuff.st_size, event_rls, 0,
				     _lua_file);
		if (err != CODE_SUCCESS) {
			fprintf(stderr,
				"load_lua_scripts: Could not dump lua buffer loaded from file: %s\n",
				_lua_file);
		} else {
			manager->rules_loaded++;
		}
	}

	err = closedir(rules_dir);
	if (err != 0) {
		fprintf(stderr,
			"load_lua_scripts: failed to close rules_dir: %d: %s\n",
			errno, strerror(errno));

		return CODE_FAILED;
	}

	printf("load_lua_script: number of rules loaded: %lu\n",
	       manager->rules_loaded);
	return CODE_SUCCESS;
}
