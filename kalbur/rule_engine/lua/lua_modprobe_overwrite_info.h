#ifndef LUA_MODPROBE_OVERWRITE_INFO_H
#define LUA_MODPROBE_OVERWRITE_INFO_H

#include <lua_process.h>

#define MODPROBE_OVERWRITE_INFO_CHUNK_SIZE 100
#define MODPROBE_OVERWRITE_INFO_ARR_METATABLE                                  \
	"ModprobeOverwriteInfoArrMetaTable"
#define MODPROBE_OVERWRITE_INFO_METATABLE "ModprobeOverwriteInfoMetaTable"
#define MODPROBE_OVERWRITE_INFO_ARR "ModprobeOverwriteInfoArr"
#define MODPROBE_OVERWRITE_INFO "ModprobeOverwriteInfo"

#define NEW_MODPROBE_PATH_ATTR "new_modprobe_path"
struct lua_modprobe_overwrite_info {
	struct lua_event_info *event_info;
	char *new_modprobe_path;
};

typedef struct lua_modprobe_overwrite_info_array {
	int max_size;
	int size;
	struct lua_modprobe_overwrite_info **values;
} lua_modprobe_overwrite_info_array;

void delete_lua_modprobe_overwrite_info(
	struct lua_modprobe_overwrite_info *modprobe_overwrite_info);
void delete_lua_modprobe_overwrite_info_array(
	struct lua_modprobe_overwrite_info_array *arr);

int modprobe_overwrite_info_index(lua_State *L);
int modprobe_overwrite_info_arr_index(lua_State *L);
int modprobe_overwrite_info_arr_len(lua_State *L);

void get_modprobe_overwrite_info(lua_State *L);

#endif // LUA_MODPROBE_OVERWRITE_INFO_H
