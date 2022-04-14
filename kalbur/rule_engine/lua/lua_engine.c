#include "lua_engine.h"
#include <lualib.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <err.h>
#include <lua_event.h>
#include <syscall_defs.h>
#include <message.h>
#include <events.h>

static void test_rule(lua_State *l)
{
	char *code = " \
		sys = Event.syscall			\
		if sys == -4 then			\
			print('Exit Event')		\
			print(Event.tgidPid)		\
			print(Event.eventTime) 		\
			print(Event.processName)	\
			print(Event.syscall)		\
		end					\
		";

	int res = luaL_dostring(l, code);
	if (res != LUA_OK) {
		printf("Error: %s\n", lua_tostring(l, -1));
	}

	return;
}

int process_rule(struct lua_engine *e, struct message_state *ms)
{
	struct probe_event_header *eh;

	eh = ms->primary_data;

	if (IS_EXIT_EVENT(eh->syscall_nr)) {
		setup_event_context(e->L, ms);

		test_rule(e->L);
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
		goto error;

	// load file and dump

	return e;
error:
	free(e);
	e = NULL;
	return NULL;
}
