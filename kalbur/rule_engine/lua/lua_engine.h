#ifndef LUA_ENGINE_H
#define LUA_ENGINE_H

#include "rule_manager.h"
#include <lua.h>
#include <message.h>

struct lua_engine {
	lua_State *L;
	struct rules_manager *manager;
};

int process_rule(struct lua_engine *e, struct message_state *ms);
struct lua_engine *initialize_new_lua_engine(void);

#endif // LUA_ENGINE_H
