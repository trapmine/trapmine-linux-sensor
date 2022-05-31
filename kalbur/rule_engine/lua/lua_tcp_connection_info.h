#ifndef LUA_TCP_CONNECTION_INFO_H
#define LUA_TCP_CONNECTION_INFO_H

#include <lua_process.h>

#define TCP_CONNECTION_INFO_CHUNK_SIZE 100
#define TCP_CONNECTION_INFO_ARR_METATABLE "TcpConnectionInfoArrMetaTable"
#define TCP_CONNECTION_INFO_METATABLE "TcpConnectionInfoMetaTable"
#define TCP_CONNECTION_INFO_ARR "TcpConnectionInfoArr"
#define TCP_CONNECTION_INFO "TcpConnectionInfo"

#define INODE_ATTR "inode"
#define INET_TYPE_ATTR "inet_type"
#define SRC_ADDR_ATTR "src_addr"
#define DST_ADDR_ATTR "dst_addr"
#define SRC_PORT_ATTR "src_port"
#define DST_PORT_ATTR "dst_port"
struct lua_tcp_connection_info {
	struct lua_event_info *event_info;
	char *type;
	char *src_addr;
	char *dst_addr;
	int src_port;
	int dst_port;
	int inode;
};

typedef struct lua_tcp_connection_info_array {
	int max_size;
	int size;
	struct lua_tcp_connection_info **values;
} lua_tcp_connection_info_array;

void delete_lua_tcp_connection_info(
	struct lua_tcp_connection_info *tcp_connection_info);
void delete_lua_tcp_connection_info_array(
	struct lua_tcp_connection_info_array *arr);

int tcp_connection_info_index(lua_State *L);
int tcp_connection_info_arr_index(lua_State *L);
int tcp_connection_info_arr_len(lua_State *L);

void get_tcp_connection_info(lua_State *L);

#endif // LUA_TCP_CONNECTION_INFO_H
