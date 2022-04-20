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
#include <syscall_defs.h>
#include "rule_manager.h"

#define LUA_EXT ".lua"

static int load_lua_chunk(lua_State *L, char *script, ssize_t file_sz)
{
	ASSERT(script != NULL, "load_lua: script == NULL");
	char *script_data;
	int fd, err;
	ssize_t rerr;
	unsigned long buff_sz;

	fd = open(script, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr,
			"load_lua_chunk: Failed to open file: %s: %d: %s\n",
			script, errno, strerror(errno));
		return CODE_FAILED;
	}

	buff_sz = (unsigned long)file_sz * sizeof(char);
	script_data = (char *)malloc(buff_sz);
	if (script_data == NULL) {
		fprintf(stderr,
			"load_lua_chunk: Failed to allocate memory for reading lua script\n");
		return CODE_FAILED;
	}

	rerr = read(fd, script_data, buff_sz);
	if (rerr == -1) {
		fprintf(stderr,
			"load_lua_chunk: Failed to read file %s: %d: %s\n",
			script, errno, strerror(errno));
		err = CODE_FAILED;
		goto out;
	}
	if (rerr < file_sz) {
		fprintf(stderr,
			"load_lua_chunk: Failed to read all bytes: %ld. Bytes read: %d\n",
			file_sz, err);
		err = CODE_FAILED;
		goto out;
	}

	err = luaL_loadbuffer(L, script_data, buff_sz, script);
	if (err != LUA_OK) {
		ASSERT(lua_isstring(L, -1), "");
		char *errstr = lua_tostring(L, -1);
		fprintf(stderr,
			"load_lua_chunk: Failed to load lua chunk: %d: %s\n",
			err, errstr);

		err = CODE_FAILED;
		goto out;
	}

	err = CODE_SUCCESS;
out:
	free(script_data);
	return err;
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

	nr = new_rule(event_rls, event_indx, filename, 256UL);
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

	if (rls != NULL) {
		for (unsigned int i = 0; i < manager->rls_sz; i++) {
			if (rls[i] != NULL) {
				free_rule_list(rls[i]);
				rls[i] = NULL;
			}
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

#define VERIFY_SZ 16UL
#define ON_EVENT_SZ 128UL
#define RULE_NAME_SZ 256UL
#define FILENAME_SZ 256UL
struct rule_config {
	char verify[VERIFY_SZ];
	char on_event[ON_EVENT_SZ];
	char rule_name[RULE_NAME_SZ];
	char filename[FILENAME_SZ];
	ssize_t file_sz;
};

static void free_rule_config(struct rule_config *rc)
{
	ASSERT(rc != NULL, "free_rule_config: rc == NULL");

	free(rc);
}

#define LUA_RULES "luaScripts"
#define RULE_FAIL 0
#define RULE_SKIP 1
#define RULE_SUCCESS 2

// This function will get the configuration information for the given script name
// and push the associated table on top of the lua stack.
// If there is no information for this rule, we signal the caller to skip loading for
// this script.
// If there is an error we fail, and propogate error to the top, resulting in aborted
// execution
static int push_rule_config_table(lua_State *L, char *rule_name)
{
	ASSERT(rule_name != NULL, "get_config_filename: rule_name == NULL");

	char *dot = strchr(rule_name, '.');
	if (dot == NULL) {
		fprintf(stderr,
			"push_rule_config_table: invalid file name. no '.lua' extension: %s\n",
			rule_name);
		return RULE_SKIP;
	}
	dot[0] = 0;

	// get the global table holding the
	// configuration for all the rules
	lua_getglobal(L, LUA_RULES);
	if (!lua_istable(L, -1)) {
		fprintf(stderr,
			"push_rule_config_table: invalid config file: rules_lua not found.\n");
		return RULE_FAIL;
	}

	// get the configuration for the given rule
	// if no configuration is present we skip this file
	lua_pushstring(L, rule_name);
	lua_gettable(L, -2);
	if (lua_isnil(L, -1)) {
		fprintf(stderr,
			"push_rule_config_table: no config for given rule: %s\n",
			rule_name);
		return RULE_SKIP;
	}
	if (!lua_istable(L, -1)) {
		fprintf(stderr,
			"push_rule_config_table: invalid config file: value of rule %s not a table\n",
			rule_name);
		return RULE_FAIL;
	}

	dot[0] = '.';

	return RULE_SUCCESS;
}

// This function gets the value of config key and saves it
// It expects the config table to be on top of the stack.
static int save_str_rule_config_key(lua_State *L, char *config_val,
				    char *key_lua, size_t value_sz)
{
	size_t sz;
	const char *str_lua;

	lua_pushstring(L, key_lua);
	lua_gettable(L, -2);
	if (!lua_isstring(L, -1)) {
		fprintf(stderr,
			"save_str_rule_config_key: invalid config structure. Value of '%s' must be string\n",
			key_lua);
		return CODE_FAILED;
	}

	str_lua = lua_tolstring(L, -1, &sz);
	if (sz >= value_sz) {
		fprintf(stderr,
			"save_str_rule_config_key: invalid config structure. Value of '%s' too long",
			key_lua);
		return CODE_FAILED;
	}
	memcpy(config_val, str_lua, sz);

	// push the config table back
	// on top of the stack
	lua_pushvalue(L, -2);

	return CODE_SUCCESS;
}

#define VERIFY_KEY "verify"
#define FILENAME_KEY "filename"
#define ON_EVENT_KEY "onEvent"
static struct rule_config *build_rule_config(lua_State *L, char *entry_name)
{
	ASSERT(entry_name != NULL, "build_rule_config: entry_name == NULL");
	int err;
	struct rule_config *rc;
	struct stat statbuff;

	rc = (struct rule_config *)calloc(1UL, sizeof(struct rule_config));
	if (rc == NULL)
		return NULL;

	char *dot = strchr(entry_name, '.');
	if (dot == NULL)
		goto fail;

	// temporarily remove file extension
	dot[0] = 0;
	memcpy(rc->rule_name, entry_name, RULE_NAME_SZ);
	// add file extension back
	dot[0] = '.';

	err = save_str_rule_config_key(L, rc->verify, VERIFY_KEY, VERIFY_SZ);
	if (err != CODE_SUCCESS)
		goto fail;

	err = save_str_rule_config_key(L, rc->filename, FILENAME_KEY,
				       FILENAME_SZ);
	if (err != CODE_SUCCESS)
		goto fail;

	err = save_str_rule_config_key(L, rc->on_event, ON_EVENT_KEY,
				       ON_EVENT_SZ);
	if (err != CODE_SUCCESS)
		goto fail;

	err = stat(rc->filename, &statbuff);
	if (err == -1) {
		fprintf(stderr,
			"build_rule_config: failed to stat file: %s: %d: %s\n",
			rc->filename, errno, strerror(errno));
		goto fail;
	}

	rc->file_sz = statbuff.st_size;

	return rc;

fail:
	free_rule_config(rc);
	rc = NULL;
	return NULL;
}

#define DEFAULT_RULES_DIR "/opt/trapmine/rules"
#define RULES_DIR "rulesDir"
static char *get_rules_directory(lua_State *L)
{
	ASSERT(L != NULL, "get_rules_directory: L == NULL");
	char *rules_dir;
	const char *str_lua;
	size_t sz;

	lua_getglobal(L, RULES_DIR);
	if (!lua_isstring(L, -1)) {
		return DEFAULT_RULES_DIR;
	}

	str_lua = lua_tolstring(L, -1, &sz);

	rules_dir = (char *)calloc(sz, sizeof(char));
	memcpy(rules_dir, str_lua, sz);

	return rules_dir;
}

#define VERIFY_NONE "none"
static int verify_script(lua_State *L, struct rule_config *rc)
{
	if (strncmp(rc->verify, "none", sizeof(VERIFY_NONE)) == 0) {
		return CODE_SUCCESS;
	}

	return CODE_FAILED;
}

static int event_index_by_name(struct rule_config *rc)
{
	printf("lua_processs exit: %d\n", LUA_PROCESS_EXIT_INDX);
	if (strncmp(rc->on_event, LUA_PROCESS_LAUNCH,
		    sizeof(LUA_PROCESS_LAUNCH)) == 0) {
		return LUA_PROCESS_LAUNCH_INDX;
	}
	if (strncmp(rc->on_event, LUA_PROCESS_EXIT, sizeof(LUA_PROCESS_EXIT)) ==
	    0) {
		return LUA_PROCESS_EXIT_INDX;
	}
	if (strncmp(rc->on_event, LUA_SOCKET_CREATE,
		    sizeof(LUA_SOCKET_CREATE)) == 0) {
		return LUA_SOCKET_CREATE_INDX;
	}
	if (strncmp(rc->on_event, LUA_SOCKET_ACCEPT,
		    sizeof(LUA_SOCKET_ACCEPT)) == 0) {
		return LUA_SOCKET_ACCEPT_INDX;
	}
	if (strncmp(rc->on_event, LUA_SOCKET_CONNECT,
		    sizeof(LUA_SOCKET_CONNECT)) == 0) {
		return LUA_SOCKET_CONNECT_INDX;
	}
	if (strncmp(rc->on_event, LUA_PTRACE, sizeof(LUA_PTRACE)) == 0) {
		return LUA_PTRACE_INDX;
	}
	if (strncmp(rc->on_event, LUA_KMODULE, sizeof(LUA_KMODULE)) == 0) {
		return LUA_KMODULE_INDX;
	}

	return -1;
}

static int load_script(lua_State *L, struct rule_config *rc,
		       struct rule_list **event_rls)
{
	ASSERT(L != NULL, "load_script: L == NULL");
	ASSERT(rc != NULL, "load_script: rc == NULL");
	int err, event_indx;

	err = verify_script(L, rc);
	if (err != CODE_SUCCESS)
		return err;

	event_indx = event_index_by_name(rc);
	if (event_indx < 0)
		return CODE_FAILED;

	err = load_lua_chunk(L, rc->filename, rc->file_sz);
	if (err != CODE_SUCCESS)
		return err;

	err = dump_lua_chunk(L, rc->file_sz, event_rls, event_indx,
			     rc->filename);

	return err;
}

int load_lua_scripts(lua_State *L, struct rules_manager *manager)
{
	ASSERT(L != NULL, "load_lua_scripts: L == NULL");
	ASSERT(manager != NULL, "load_lua_scripts: manager == NULL");

	int err;
	struct dirent *entry;
	char *rules_dir;
	DIR *dir;
	struct rule_list **event_rls;
	struct rule_config *rc;

	// get the directory where the rule files
	// are kept
	rules_dir = get_rules_directory(L);
	if (rules_dir == NULL)
		return CODE_FAILED;

	// acquire a handle on the directory
	dir = opendir(rules_dir);
	if (dir == NULL) {
		fprintf(stderr, "load_lua_scripts: Failed to open %s: %d: %s\n",
			rules_dir, errno, strerror(errno));

		free(rules_dir);
		return CODE_FAILED;
	}

	event_rls = manager->event_rls;
	ASSERT(event_rls != NULL, "load_lua_scripts: event_rls == NULL");

	// Loop over all the files in this directory and try to load
	// any file with the extension '.lua'
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_REG)
			continue;

		ASSERT(entry->d_name != NULL,
		       "load_lua_scripts: d_name == NULL");
		if (strstr(entry->d_name, LUA_EXT) == NULL)
			continue;

		err = push_rule_config_table(L, entry->d_name);
		if (err == RULE_SKIP)
			continue;
		if (err == RULE_FAIL)
			return CODE_FAILED;

		rc = build_rule_config(L, entry->d_name);
		if (rc == NULL)
			continue;

		err = load_script(L, rc, event_rls);
		if (err != CODE_SUCCESS) {
			fprintf(stderr,
				"load_lua_scripts: Failed to load lua script: %s\n",
				rc->filename);
		} else {
			manager->rules_loaded++;
		}

		free_rule_config(rc);
	}

	err = closedir(dir);
	if (err != 0) {
		fprintf(stderr,
			"load_lua_scripts: failed to close directory: %d: %s\n",
			errno, strerror(errno));

		return CODE_FAILED;
	}

	printf("load_lua_scripts: number of rules loaded: %lu\n",
	       manager->rules_loaded);
	return CODE_SUCCESS;
}

int get_event_indx(int syscall)
{
	if (IS_EXIT_EVENT(syscall)) {
		return LUA_PROCESS_EXIT_INDX;
	}
	if (IS_PROCESS_LAUNCH(syscall)) {
		return LUA_PROCESS_LAUNCH_INDX;
	}
	if (IS_SOCKET_CREATE(syscall)) {
		return LUA_SOCKET_CREATE_INDX;
	}
	if (syscall == SYS_ACCEPT) {
		return LUA_SOCKET_ACCEPT_INDX;
	}
	if (syscall == SYS_CONNECT) {
		return LUA_SOCKET_CONNECT_INDX;
	}
	if (syscall == SYS_PTRACE) {
		return LUA_PTRACE_INDX;
	}
	if (syscall == SYS_FINIT_MODULE) {
		return LUA_KMODULE_INDX;
	} else {
		return LUA_NONE;
	}
}
