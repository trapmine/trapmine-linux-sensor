#ifndef LUA_ENGINE_H
#define LUA_ENGINE_H

#include "rule_manager.h"
#include "engine.h"
#include <lua.h>
#include <message.h>

struct lua_engine {
	lua_State *L;
	struct rules_manager *manager;
};

int apply_rules(struct engine *e, struct message_state *ms);
struct lua_engine *initialize_new_lua_engine(struct rules_manager *manager);
struct rules_manager *init_rules_manager(char *config_file);

#endif // LUA_ENGINE_H
