#include "lua_engine.h"
#include <lualib.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <err.h>

static void test_rule(lua_State *l)
{
	char *code = "print('Hello, from inside lua')";

	if (luaL_loadstring(l, code) == LUA_OK) {
		if (lua_pcall(l, 0, 0, 0) == LUA_OK) {
			lua_pop(l, lua_gettop(l));
		}
	}

	return;
}

int process_rule(struct lua_engine *e, struct message_state *ms)
{
	struct probe_event_header *eh;

	ASSERT(ms != NULL, "process_rule: ms == NULL");
	eh = (struct probe_event_header *)ms->primary_data;

	test_rule(e->L);

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
	//	luaopen_trapmine(l);
}

struct lua_engine *initialize_new_lua_engine(void)
{
	struct lua_engine *e;

	e = calloc(1UL, sizeof(struct lua_engine));
	if (e == NULL)
		goto out;

	e->L = new_state();
	if (e->L == NULL)
		goto error;

	initialize_state(e->L);

	// load file and dump

out:
	return e;
error:
	free(e);
	e = NULL;
	return NULL;
}
