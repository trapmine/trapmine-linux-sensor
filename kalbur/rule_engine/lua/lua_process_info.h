#ifndef LUA_PROCESS_INFO_H
#define LUA_PROCESS_INFO_H

#include <lua_process.h>

#define PROCESS_INFO_CHUNK_SIZE 100
#define PROCESS_METATABLE "ProcessMetaTable"
#define PROCESS_INFO "ProcessInfo"

struct lua_process_info {
	struct lua_event_info *event_info;
	u64_t ppid;
};

typedef struct lua_process_info_array {
	int max_size;
	int size;
	struct lua_process_info **values;
} lua_process_info_array;

void delete_lua_process_info(struct lua_process_info *process_info);
void delete_lua_process_info_array(struct lua_process_info_array *arr);

#endif // LUA_PROCESS_INFO_H