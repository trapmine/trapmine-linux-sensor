#ifndef LUA_PROCESS_LPE_INFO_H
#define LUA_PROCESS_LPE_INFO_H

#include <lua_process.h>

#define PROCESS_LPE_INFO_CHUNK_SIZE 100
#define PROCESS_LPE_INFO_ARR_METATABLE "ProcessLPEInfoArrMetaTable"
#define PROCESS_LPE_INFO_METATABLE "ProcessLPEInfoMetaTable"
#define PROCESS_LPE_INFO_ARR "ProcessLPEInfoArr"
#define PROCESS_LPE_INFO "ProcessLPEInfo"

#define CALLER_RET_ADDR_ATTR "caller_ret_addr"
#define TARGET_FUNC_ATTR "target_func"
struct lua_process_lpe_info {
	struct lua_event_info *event_info;
	u64_t caller_ret_addr;
	char *target_func;
};

typedef struct lua_process_lpe_info_array {
	int max_size;
	int size;
	struct lua_process_lpe_info **values;
} lua_process_lpe_info_array;

void delete_lua_process_lpe_info(struct lua_process_lpe_info *process_lpe_info);
void delete_lua_process_lpe_info_array(struct lua_process_lpe_info_array *arr);

int process_lpe_info_index(lua_State *L);
int process_lpe_info_arr_index(lua_State *L);
int process_lpe_info_arr_len(lua_State *L);

void get_process_lpe_info(lua_State *L);

#endif // LUA_PROCESS_LPE_INFO_H
