#ifndef LUA_PTRACE_INFO_H
#define LUA_PTRACE_INFO_H

#include <lua_process.h>

#define PTRACE_INFO_CHUNK_SIZE 100
#define PTRACE_INFO_ARR_METATABLE "PtraceInfoArrMetaTable"
#define PTRACE_INFO_METATABLE "PtraceInfoMetaTable"
#define PTRACE_INFO_ARR "PtraceInfoArr"
#define PTRACE_INFO "PtraceInfo"

#define REQUEST_ATTR "request"
#define ADDR_ATTR "addr"
#define TARGET_TGID_ATTR "target_pid"
struct lua_ptrace_info {
	struct lua_event_info *event_info;
	u64_t request;
	u64_t addr;
	u64_t target_tgid;
};

typedef struct lua_ptrace_info_array {
	int max_size;
	int size;
	struct lua_ptrace_info **values;
} lua_ptrace_info_array;

void delete_lua_ptrace_info(struct lua_ptrace_info *ptrace_info);
void delete_lua_ptrace_info_array(struct lua_ptrace_info_array *arr);

int ptrace_info_index(lua_State *L);
int ptrace_info_arr_index(lua_State *L);
int ptrace_info_arr_len(lua_State *L);

void get_ptrace_info(lua_State *L);

#endif // LUA_PTRACE_INFO_H
