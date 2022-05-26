#ifndef LUA_PROCESS_INFO_H
#define LUA_PROCESS_INFO_H

#include <lua_process.h>

#define PROCESS_INFO_CHUNK_SIZE 100
#define PROCESS_INFO_ARR_METATABLE "ProcessInfoArrMetaTable"
#define PROCESS_INFO_METATABLE "ProcessInfoMetaTable"
#define PROCESS_INFO_ARR "ProcessInfoArr"
#define PROCESS_INFO "ProcessInfo"

#define PARENT_PID_ATTR "ppid"
#define CLONE_FLAGS_ATTR "clone_flags"
#define ARGS_ATTR "args"
#define ENV_ATTR "env"
#define INTERPRETER_ATTR "interpreter"
#define UID_ATTR "uid"
#define GID_ATTR "gid"
#define EUID_ATTR "euid"
#define EGID_ATTR "egid"
#define STDIN_INODE_ATTR "stdin_inode"
#define STDOUT_INODE_ATTR "stdout_inode"
#define STDERR_INODE_ATTR "stderr_inode"
#define STDIN_TYPE_ATTR "stdin_type"
#define STDOUT_TYPE_ATTR "stdout_type"
#define STDERR_TYPE_ATTR "stderr_type"
struct lua_process_info {
	struct lua_event_info *event_info;
	u64_t parent_tgid;
	u64_t clone_flags;
	char *args;
	char *env;
	char *interpreter;
	int uid;
	int gid;
	int euid;
	int egid;
	int stdin_inode;
	int stdin_type;
	int stdout_inode;
	int stdout_type;
	int stderr_inode;
	int stderr_type;
	struct lua_file_info *file_info;
};

typedef struct lua_process_info_array {
	int max_size;
	int size;
	struct lua_process_info **values;
} lua_process_info_array;

void delete_lua_process_info(struct lua_process_info *process_info);
void delete_lua_process_info_array(struct lua_process_info_array *arr);

int process_info_index(lua_State *L);
int process_info_arr_index(lua_State *L);
int process_info_arr_len(lua_State *L);

void get_process_info(lua_State *L);

#endif // LUA_PROCESS_INFO_H
