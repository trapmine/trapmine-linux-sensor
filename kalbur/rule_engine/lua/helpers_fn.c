#include <lua.h>
#include <lauxlib.h>
#include <err.h>
#include <message.h>
#include "lua_event.h"
#include "helpers_fn.h"

int tag_event(lua_State *L)
{
	ASSERT(L != NULL, "tag_event: L == NULL");
	struct message_state *ms;
	unsigned long tag;
	int err;

	err = lua_isinteger(L, -1);
	if (err != 1) {
		luaL_error(
			L,
			"Exepected integer as the first argument of TagEvent\n");
		return 0;
	}
	tag = (unsigned long)lua_tointeger(L, -1);

	lua_getglobal(L, EVENT_GLOBAL);
	err = lua_isuserdata(L, -1);
	if (err != 1) {
		luaL_error(L, "Could not get global 'Event'\n");
		return 0;
	}

	struct lua_event *event = (struct lua_event *)lua_touserdata(L, -1);
	if (event == NULL) {
		luaL_error(L, "'Event' userdata cannot be NULL\n");
		return 0;
	}

	ms = (struct message_state *)event->ms;
	if (ms == NULL) {
		luaL_error(
			L,
			"Unexpected value of 'ms_event' field of userdata 'Event'. ms_event == %p\n",
			ms);
		return 0;
	}

	tag_ms(ms, tag);

	return 0;
}
