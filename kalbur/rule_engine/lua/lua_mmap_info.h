#ifndef LUA_MMAP_INFO_H
#define LUA_MMAP_INFO_H

#include <lua_process.h>

#define MMAP_INFO_CHUNK_SIZE 100
#define MMAP_INFO_ARR_METATABLE "MmapInfoArrMetaTable"
#define MMAP_INFO_METATABLE "MmapInfoMetaTable"
#define MMAP_INFO_ARR "MmapInfoArr"
#define MMAP_INFO "MmapInfo"

#define VM_BASE "vm_base"
#define FILE "file"
struct lua_mmap_info {
	struct lua_event_info *event_info;
	u64_t vm_base;
	struct lua_file_info *file_info;
};

typedef struct lua_mmap_info_array {
	int max_size;
	int size;
	struct lua_mmap_info **values;
} lua_mmap_info_array;

void delete_lua_mmap_info(struct lua_mmap_info *mmap_info);
void delete_lua_mmap_info_array(struct lua_mmap_info_array *arr);

int mmap_info_index(lua_State *L);
int mmap_info_arr_index(lua_State *L);
int mmap_info_arr_len(lua_State *L);

void get_mmap_info(lua_State *L);

#endif // LUA_MMAP_INFO_H