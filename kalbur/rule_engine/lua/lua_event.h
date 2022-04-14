#ifndef LUA_EVENT_H
#define LUA_EVENT_H
#include <lua.h>
#include <message.h>

#define EVENT_METATABLE "EventMetaTable"

typedef void (*push_attr_fn)(lua_State *L, const char *attr_name,
			     void *event_obj);

struct lua_event {
	push_attr_fn push_attr;
	void *ms_event;
};

int initialize_event_metatable(lua_State *L);
void setup_event_context(lua_State *L, struct message_state *ms);
int init_event_context(lua_State *L);

#endif // LUA_EVENT_H
