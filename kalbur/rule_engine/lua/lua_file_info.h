#ifndef LUA_FILE_INFO_H
#define LUA_FILE_INFO_H

#include <lua_process.h>

#define FILE_INFO "FileInfo"
#define FILE_INFO_METATABLE "FileInfoMetaTable"

#define FILENAME "filename"
#define INODE "inode"
#define S_MAGIC "s_magic"
struct lua_file_info {
	char *filename;
	u64_t inode;
	u64_t s_magic;
};

void delete_lua_file_info(struct lua_file_info *file_info);
int file_info_index(lua_State *L);

#endif // LUA_FILE_INFO_H
