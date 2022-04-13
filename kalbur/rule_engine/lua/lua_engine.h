#ifndef LUA_ENGINE_H
#define LUA_ENGINE_H

#include <lua.h>

struct lua_engine {
	lua_State *L;
};

int process_rule(struct lua_engine *e);
struct lua_engine *initialize_new_lua_engine(void);

#endif // LUA_ENGINE_H
