#ifndef LUA_SOCKET_CREATE_INFO_H
#define LUA_SOCKET_CREATE_INFO_H

#include <lua_process.h>

#define SOCKET_CREATE_INFO_CHUNK_SIZE 100
#define SOCKET_CREATE_INFO_ARR_METATABLE "SocketCreateInfoArrMetaTable"
#define SOCKET_CREATE_INFO_METATABLE "SocketCreateInfoMetaTable"
#define SOCKET_CREATE_INFO_ARR "SocketCreateInfoArr"
#define SOCKET_CREATE_INFO "SocketCreateInfo"

#define INODE_ATTR "inode"
#define FAMILY_ATTR "family"
#define SOCKET_TYPE_ATTR "socket_type"
struct lua_socket_create_info {
	struct lua_event_info *event_info;
	u64_t inode;
	char *family;
	char *socket_type;
};

typedef struct lua_socket_create_info_array {
	int max_size;
	int size;
	struct lua_socket_create_info **values;
} lua_socket_create_info_array;

void delete_lua_socket_create_info(
	struct lua_socket_create_info *socket_create_info);
void delete_lua_socket_create_info_array(
	struct lua_socket_create_info_array *arr);

int socket_create_info_index(lua_State *L);
int socket_create_info_arr_index(lua_State *L);
int socket_create_info_arr_len(lua_State *L);

void get_socket_create_info(lua_State *L);

#endif // LUA_SOCKET_CREATE_INFO_H
