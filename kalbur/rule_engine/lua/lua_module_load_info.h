#ifndef LUA_MODULE_LOAD_INFO_H
#define LUA_MODULE_LOAD_INFO_H

#include <lua_process.h>

#define MODULE_LOAD_INFO_CHUNK_SIZE 100
#define MODULE_LOAD_INFO_ARR_METATABLE "ModuleLoadInfoArrMetaTable"
#define MODULE_LOAD_INFO_METATABLE "ModuleLoadInfoMetaTable"
#define MODULE_LOAD_INFO_ARR "ModuleLoadInfoArr"
#define MODULE_LOAD_INFO "ModuleLoadInfo"

#define FILE "file"
struct lua_module_load_info {
	struct lua_event_info *event_info;
	struct lua_file_info *file_info;
};

typedef struct lua_module_load_info_array {
	int max_size;
	int size;
	struct lua_module_load_info **values;
} lua_module_load_info_array;

void delete_lua_module_load_info(struct lua_module_load_info *module_load_info);
void delete_lua_module_load_info_array(struct lua_module_load_info_array *arr);

int module_load_info_index(lua_State *L);
int module_load_info_arr_index(lua_State *L);
int module_load_info_arr_len(lua_State *L);

void get_module_load_info(lua_State *L);

#endif // LUA_MODULE_LOAD_INFO_H