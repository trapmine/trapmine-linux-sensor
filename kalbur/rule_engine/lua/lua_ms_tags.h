#ifndef LUA_MS_TAGS_H
#define LUA_MS_TAGS_H

#include <lua.h>

#define HASHLOOKUP_ACTION 1
#define ALERT_ACTION 2
#define KILL_PROCESS_ACTION 3

int initialize_tags(lua_State *L);

#endif // LUA_MS_TAGS_H
