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
#include "lua_tcp_connection_info.h"
#include "lua_module_load_info.h"
#include "lua_modprobe_overwrite_info.h"
#include "lua_process_lpe_info.h"
#include "lua_helpers.h"

#define GLOBAL_PID_LIST "SENSOR_PID_LIST"
#define PROCESS_METATABLE "ProcessMetaTable"

#define IS_ATTR(attr_name, attr) strncmp(attr_name, attr, sizeof(attr)) == 0

// TODO: check which process is live with the event_time and exit event.

#define PID "pid"
struct lua_process_context {
	int pid;
	struct lua_process_info_array *process_info_arr;
	struct lua_mmap_info_array *mmap_info_arr;
	struct lua_ptrace_info_array *ptrace_info_arr;
	struct lua_socket_create_info_array *socket_create_info_arr;
	struct lua_tcp_connection_info_array *tcp_connection_info_arr;
	struct lua_module_load_info_array *module_load_info_arr;
	struct lua_modprobe_overwrite_info_array *modprobe_overwrite_info_arr;
	struct lua_process_lpe_info_array *process_lpe_info_arr;
};

void get_global_pid_list(lua_State *L);
void get_global_pid(lua_State *L, int pid);

int process_index(lua_State *L);
int get_process_by_pid(lua_State *L);
int get_pid_by_event_id(lua_State *L);
int get_stdout_by_stdin(lua_State *L);
int get_stdin_by_stdout(lua_State *L);

void teardown_process_context(lua_State *L);
void init_process_context(lua_State *L);

#endif // LUA_PROCESS_H
