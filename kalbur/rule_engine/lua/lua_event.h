#ifndef LUA_EVENT_H
#define LUA_EVENT_H
#include <lua.h>
#include <message.h>

#define EVENT_METATABLE "EventMetaTable"
#define EVENT_GLOBAL "Event"

typedef void (*push_attr_fn)(lua_State *L, const char *attr_name,
			     struct message_state *event_obj);

struct lua_event {
	push_attr_fn push_attr;
	void *ms;
};

void setup_event_context(lua_State *L, struct message_state *ms);
void teardown_event_context(lua_State *L);
int init_event_context(lua_State *L);

#endif // LUA_EVENT_H
