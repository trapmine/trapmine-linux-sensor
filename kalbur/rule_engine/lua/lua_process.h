#ifndef LUA_PROCESS_H
#define LUA_PROCESS_H

#include <string.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <hash.h>
#include <sqlite3.h>

#include "err.h"
#include "database.h"
#include "lua_event_info.h"
#include "lua_file_info.h"
#include "lua_process_info.h"
#include "lua_mmap_info.h"
#include "lua_ptrace_info.h"
#include "lua_socket_create_info.h"

#define GLOBAL_LUA_DB "SENSOR_DB"
#define GLOBAL_PID_LIST "SENSOR_PID_LIST"
#define PROCESS_METATABLE "ProcessMetaTable"

#define IS_ATTR(attr_name, attr) strncmp(attr_name, attr, sizeof(attr)) == 0

// TODO: check which process is live with the event_time and exit event.

struct lua_db {
	sqlite3 *db;
	hashtable_t *sqlite_stmts;
};

#define PID "pid"
struct lua_process_context {
	int pid;
	struct lua_process_info_array *process_info_arr;
	struct lua_mmap_info_array *mmap_info_arr;
	struct lua_ptrace_info_array *ptrace_info_arr;
	struct lua_socket_create_info_array *socket_create_info_arr;
};

struct lua_db *get_lua_db(lua_State *L);
void get_global_pid_list(lua_State *L);
void get_global_pid(lua_State *L, int pid);

int process_index(lua_State *L);
int get_process_by_pid(lua_State *L);

void teardown_process_context(lua_State *L);
void init_process_context(lua_State *L, sqlite3 *db, hashtable_t *sqlite_stmts);

#endif // LUA_PROCESS_H
