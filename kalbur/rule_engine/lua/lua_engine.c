#include <lualib.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <err.h>
#include <lua_event.h>
#include <syscall_defs.h>
#include <message.h>
#include <events.h>
#include "lua_ms_tags.h"
#include "lua_engine.h"
#include "rule_manager.h"

static int execute_bytecode(lua_State *L, char *bytecode, size_t bytecode_sz,
			    char *script_name)
{
	ASSERT(L != NULL, "execute_bytecode: L == NULL");
	ASSERT(bytecode != NULL, "execute_bytecode: bytecode == NULL");
	int err;

	err = luaL_loadbuffer(L, bytecode, bytecode_sz, script_name);
	if (err != LUA_OK) {
		fprintf(stderr,
			"execute_bytecode: Failed to load bytecode into lua for script: %s\n",
			script_name);
		return CODE_FAILED;
	}

	if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
		fprintf(stderr,
			"execute_bytecode: error while running bytecode: %s\n",
			lua_tostring(L, -1));
		return CODE_FAILED;
	}

	lua_settop(L, 0);

	return CODE_SUCCESS;
}

static void evaluate_rule_list(lua_State *L, struct rule_list *r)
{
	int err;
	while (r != NULL) {
		err = execute_bytecode(L, r->rule_bytecode, r->bytecode_sz,
				       r->script_name);
		if (err != CODE_SUCCESS) {
			fprintf(stderr,
				"process_rule: Failed to execute bytecode from: %s\n",
				r->script_name);
		}

		r = r->next_rule;
	}
}

int apply_rules(struct engine *e, struct message_state *ms)
{
	int event_indx;
	struct probe_event_header *eh;
	struct rule_list **event_rls;
	struct rule_list *r;
	struct lua_engine *le = e->le;

	ASSERT(ms != NULL, "process_rule: ms == NULL");
	ASSERT(ms->primary_data != NULL,
	       "process_rule: ms->primary_data == NULL");
	eh = (struct probe_event_header *)ms->primary_data;
	event_indx = get_event_indx(eh->syscall_nr);
	// no rule list for this type of event
	if (event_indx == LUA_NONE)
		return CODE_SUCCESS;

	ASSERT(le->manager != NULL, "process_rule: manager == NULL");
	event_rls = le->manager->event_rls;
	ASSERT(event_rls != NULL, "process_rule: event_rls == NULL");

	setup_event_context(le->L, ms);

	// evaluate rule for any event
	r = event_rls[LUA_ANY];
	if (r != NULL)
		evaluate_rule_list(le->L, r);

	// evaluate rule for specific event
	r = event_rls[event_indx];
	if (r != NULL)
		evaluate_rule_list(le->L, r);

	teardown_event_context(le->L);

	return CODE_SUCCESS;
}

static void initialize_state(lua_State *l)
{
	luaopen_base(l);
	luaopen_string(l);
	luaopen_utf8(l);
	luaopen_table(l);
	luaopen_math(l);
}

struct lua_engine *
initialize_new_lua_engine(struct rules_manager *read_only_manager)
{
	ASSERT(read_only_manager != NULL,
	       "initialize_new_lua_engine: manager == NULL");

	int err;
	struct lua_engine *e;

	e = calloc(1UL, sizeof(struct lua_engine));
	if (e == NULL)
		return NULL;

	e->manager = read_only_manager;

	e->L = luaL_newstate();
	if (e->L == NULL)
		goto error;

	initialize_state(e->L);

	err = init_event_context(e->L);
	if (err != CODE_SUCCESS)
		goto close_state;

	err = initialize_tags(e->L);
	if (err != CODE_SUCCESS)
		goto close_state;

	return e;

close_state:
	lua_close(e->L);
	e->L = NULL;
error:
	free(e);
	e = NULL;
	return NULL;
}

struct rules_manager *init_rules_manager(char *config_file)
{
	int err;
	lua_State *L;

	struct rules_manager *new =
		new_rules_manager(TYPED_MACRO(TOTAL_EVENTS, UL));
	if (new == NULL)
		return NULL;

	L = luaL_newstate();
	if (L == NULL)
		goto fail;

	err = luaL_dofile(L, config_file);
	if (err != LUA_OK) {
		char *errstr = lua_tostring(L, -1);
		fprintf(stderr,
			"init_rules_manager: failed to load configuration file: %s: %s\n",
			config_file, errstr);
		goto close_state;
	}

	err = load_lua_scripts(L, new);
	if (err != CODE_SUCCESS) {
		fprintf(stderr,
			"init_rules_manager: Failed to load lua scripts\n");
		goto close_state;
	}

	lua_close(L);
	return new;

close_state:
	lua_close(L);
	L = NULL;
fail:
	free_rules_manager(new);
	new = NULL;
	return NULL;
}
