#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include <lua.h>

#define INCR __COUNTER__
#define PROCESS_LAUNCH_EVENT __COUNTER__
#define SOCKET_CREATE_EVENT __COUNTER__
#define SOCKET_ACCEPT_EVENT __COUNTER__
#define SOCKET_CONNECT_EVENT __COUNTER__
#define SOCKET_CONNECT_OR_ACCEPT_EVENT __COUNTER__
#define PTRACE_EVENT __COUNTER__
#define LOAD_MODULE_EVENT __COUNTER__

#define TOTAL_EVENTS __COUNTER__

struct rule_list {
	size_t bytecode_sz;
	char *rule_bytecode;
	char *script_name;
	struct rule_list *next_rule;
};

struct rules_manager {
	struct rule_list **event_rls;
	size_t rls_sz;
	unsigned long rules_loaded;
};

int load_lua_scripts(lua_State *L, struct rules_manager *manager);
struct rules_manager *new_rules_manager(size_t rls_sz);
void free_rules_manager(struct rules_manager *manager);

#endif // RULE_MANAGER_H
