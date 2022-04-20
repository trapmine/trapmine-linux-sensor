#include <err.h>
#include <events.h>
#include <lauxlib.h>
#include "lua_event.h"
#include "attr_handler.h"

// This is a function of the type lua_CFunction. It is called by lua.
// This function is called whenever the global 'Event' userdata
// is indexed, i.e, if an attribute is accessed like Event.tgidPid
// This functions called the attribute handler associated with the
// userdata, to push the correct value onto the stack.
static int event_index(lua_State *L)
{
	ASSERT(lua_isuserdata(L, -2), "event_index: stack[-2] not userdata");
	ASSERT(lua_isstring(L, -1), "event_index: stack[-1] not string");

	struct lua_event *event = (struct lua_event *)lua_touserdata(L, -2);
	if (event == NULL) {
		lua_pushnil(L);
		return 1;
	}
	void *ms_event = event->ms_event;

	const char *attr = lua_tostring(L, -1);
	if (attr == NULL) {
		lua_pushnil(L);
		return 1;
	}

	ASSERT(event->push_attr != NULL,
	       "event_index: event->push_att == NULL");
	event->push_attr(L, attr, ms_event);

	return 1;
}

// This function sets up the global 'Event' object userdata.
// We need to provide the primary_data of the incoming event.
// And we need to provide the function which lookups the values
// of the attributes.
void setup_event_context(lua_State *L, struct message_state *ms)
{
	ASSERT(ms != NULL, "setup_event_context: ms == NULL");
	ASSERT(ms->primary_data != NULL,
	       "setup_event_context: ms->primary == NULL");

	struct probe_event_header *eh =
		(struct probe_event_header *)ms->primary_data;

	lua_getglobal(L, EVENT_GLOBAL);
	struct lua_event *global_lua_event =
		(struct lua_event *)lua_touserdata(L, -1);
	ASSERT(global_lua_event != NULL,
	       "setup_event_context: global_lua_event == NULL");

	global_lua_event->push_attr = get_push_attr_fn(eh->syscall_nr);
	ASSERT(global_lua_event->push_attr != NULL,
	       "setup_event_context: global_lua_event->push_attr == NULL");

	global_lua_event->ms_event = ms->primary_data;
	global_lua_event->ms = ms;

	return;
}

void teardown_event_context(lua_State *L)
{
	ASSERT(L != NULL, "teardown_event_context: L == NULL");

	lua_getglobal(L, EVENT_GLOBAL);
	struct lua_event *global_lua_event =
		(struct lua_event *)lua_touserdata(L, -1);
	ASSERT(global_lua_event != NULL,
	       "teardown_event_context: global_lua_event == NULL");

	__builtin_memset(global_lua_event, 0, sizeof(struct lua_event));
	return;
}

// This function exposes the incoming event as a global 'Event' variable
// inside the lua script. The script can then access the fields of the
// incoming message as attributes of this 'Event' object.
//
// This function creates the userdata underlying the 'Event' object.
// It associates a metatable with this userdata.
// Finally it provides a handler for the __index metamethod. This
// is actually responsible for figuring out the type of the event
// and returning the correct value for the attribute being accessed.
int init_event_context(lua_State *L)
{
	ASSERT(L != NULL, "init_event_context: L == NULL");

	// create userdata underlying the global 'Event' object.
	struct lua_event *global_lua_event =
		(struct lua_event *)lua_newuserdata(L,
						    sizeof(struct lua_event));
	if (global_lua_event == NULL) {
		goto fail;
	}

	// create new metatable to associate with 'Event' object
	luaL_newmetatable(L, EVENT_METATABLE);

	// Set event_index as the function to be called when
	// userdata attributed are accessed inside the lua script
	lua_pushstring(L, "__index");
	lua_pushcfunction(L, event_index);
	lua_settable(L, -3);

	// sanity checks
	ASSERT(lua_istable(L, -1), "");
	ASSERT(lua_isuserdata(L, -2), "");
	// set metatable of global_lua_event
	lua_setmetatable(L, -2);

	// since metatable is poped off the stack the
	// userdata should now be at the top. Make sure.
	ASSERT(lua_isuserdata(L, -1), "");

	// expose the userdata as a global value to the lua script
	lua_setglobal(L, EVENT_GLOBAL);

	return CODE_SUCCESS;

fail:
	lua_settop(L, 0);

	// Delete the function associated with __index
	luaL_getmetatable(L, EVENT_METATABLE);
	lua_pushnil(L);
	lua_setfield(L, -2, "__index");

	// delete metatable
	lua_pushnil(L);
	lua_setfield(L, LUA_REGISTRYINDEX, EVENT_METATABLE);

	lua_settop(L, 0);
	return CODE_FAILED;
}
