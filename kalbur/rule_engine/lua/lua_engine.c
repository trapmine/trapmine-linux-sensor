#include <lualib.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <err.h>
#include <lua_event.h>
#include <syscall_defs.h>
#include <message.h>
#include <events.h>
#include "lua_engine.h"
#include "rule_manager.h"

//static void test_rule(lua_State *l)
//{
//	char *code =
//		"print(Event.type)\nprint(Event.family)\nprint(Event.inode)\nprint(Event.syscall)";
//
//	int res = luaL_dostring(l, code);
//	if (res != LUA_OK) {
//		printf("Error: %s\n", lua_tostring(l, -1));
//	}
//
//	return;
//}

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

	return CODE_SUCCESS;
}

int process_rule(struct lua_engine *e, struct message_state *ms)
{
	int event_indx, err;
	struct probe_event_header *eh;
	struct rule_list **event_rls;
	struct rule_list *r;

#ifdef __DEBUG__
	int i = 0;
#endif

	event_indx = 0;
	ASSERT(e->manager != NULL, "process_rule: manager == NULL");
	event_rls = e->manager->event_rls;
	ASSERT(event_rls != NULL, "process_rule: event_rls == NULL");

	eh = ms->primary_data;
	if (IS_EXIT_EVENT(eh->syscall_nr)) {
		setup_event_context(e->L, ms);

		r = event_rls[event_indx];
		while (r != NULL) {
#ifdef __DEBUG__
			printf("%d] process_rule: executing script: %s\n", i++,
			       r->script_name);
#endif
			err = execute_bytecode(e->L, r->rule_bytecode,
					       r->bytecode_sz, r->script_name);
			if (err != CODE_SUCCESS) {
				fprintf(stderr,
					"process_rule: Failed to execute bytecode from: %s\n",
					r->script_name);
			}

			r = r->next_rule;
		}
	}

	return CODE_SUCCESS;
}

static lua_State *new_state(void)
{
	return luaL_newstate();
}

static void initialize_state(lua_State *l)
{
	luaopen_base(l);
	luaopen_string(l);
	luaopen_utf8(l);
	luaopen_table(l);
	luaopen_math(l);
}

// Expects lua_State to have been closed already.
// lua_close(L) closes the lua_State object and
// frees the points as well
static void free_lua_engine(struct lua_engine *e)
{
	ASSERT(e->L == NULL, "free_lua_engine: e->L != NULL");

	if (e->manager != NULL) {
		free_rules_manager(e->manager);
		e->manager = NULL;
	}

	free(e);
}

struct lua_engine *initialize_new_lua_engine(void)
{
	int err;
	struct lua_engine *e;

	e = calloc(1UL, sizeof(struct lua_engine));
	if (e == NULL)
		return NULL;

	e->L = new_state();
	if (e->L == NULL)
		goto error;

	initialize_state(e->L);

	err = init_event_context(e->L);
	if (err != CODE_SUCCESS)
		goto close_state;

	e->manager = new_rules_manager(TYPED_MACRO(TOTAL_EVENTS, UL));
	if (e->manager == NULL)
		goto close_state;

	err = load_lua_scripts(e->L, e->manager);
	if (err != CODE_SUCCESS)
		goto close_state;

	return e;

close_state:
	lua_close(e->L);
	e->L = NULL;
error:
	free_lua_engine(e);
	e = NULL;
	return NULL;
}
