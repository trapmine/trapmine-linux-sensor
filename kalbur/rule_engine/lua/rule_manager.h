#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include <lua.h>

#define LUA_NONE -1
#define LUA_ANY 0
#define LUA_PROCESS_LAUNCH_INDX 1
#define LUA_PROCESS_EXIT_INDX 2
#define LUA_SOCKET_CREATE_INDX 3
#define LUA_SOCKET_ACCEPT_INDX 4
#define LUA_SOCKET_CONNECT_INDX 5
#define LUA_PTRACE_INDX 6
#define LUA_KMODULE_INDX 7
#define TOTAL_EVENTS 8

#define LUA_PROCESS_LAUNCH "process-launch"
#define LUA_PROCESS_EXIT "exit"
#define LUA_SOCKET_CREATE "socket-create"
#define LUA_SOCKET_ACCEPT "socket-accept"
#define LUA_SOCKET_CONNECT "socket-connect"
#define LUA_PTRACE "ptrace"
#define LUA_KMODULE "kernel-module-load"

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
int get_event_indx(int syscall);

#endif // RULE_MANAGER_H
