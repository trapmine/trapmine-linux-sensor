#ifndef LUA_EVENT_INFO_H
#define LUA_EVENT_INFO_H

#include <lua_process.h>

#define EVENT_TIME "event_time"
#define SYSCALL "syscall"
#define PROCESS_NAME "process_name"
struct lua_event_info {
	u64_t event_time;
	int syscall;
	char *process_name;
};

void delete_lua_event_info(struct lua_event_info *event_info);

#endif // LUA_EVENT_INFO_H
