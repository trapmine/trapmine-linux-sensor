#include "lua_process.h"

/**
 * @brief Get the global pid list object.
 * Stack: [-0, +1]
 * 
 * @param L Lua state
 * Stack: [-0, +1]
 */
void get_global_pid_list(lua_State *L)
{
	lua_pushstring(L, GLOBAL_PID_LIST);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ASSERT(lua_istable(L, -1), "get_global_pid_list: stack[-1] not table");
}

/**
 * @brief Get the global pid object from the pid list.
 * if pid exists in the list, it returns userdata.
 * otherwise nil.
 * Stack: [-0, +1]
 * 
 * @param L 
 * @param pid
 */
void get_global_pid(lua_State *L, int pid)
{
	// get REGISTRY[GLOBAL_PID_LIST][pid] on top
	// of the stack
	get_global_pid_list(L);
	lua_pushinteger(L, (lua_Integer)pid);
	lua_gettable(L, -2);
	lua_rotate(L, -2, 1);
	lua_pop(L, 1);
}

/**
 * @brief handle index access of process_context
 * Expects stack to have string attribute at the top
 * and proces_context user data at position -2.
 * returns nil if error occurs.
 * 
 * Stack: [-2, +1]
 * @param L
 * @return number of return values (1)
 */
int process_index(lua_State *L)
{
	struct lua_process_context *process_context;
	const char *attr;

	// get the process context userdata.
	process_context = (struct lua_process_context *)lua_touserdata(L, -2);
	if (process_context == NULL) {
		fprintf(stderr, "process_index: process_context == NULL\n");
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}

	// get the attribute name.
	attr = lua_tostring(L, -1);
	if (attr == NULL) {
		fprintf(stderr, "process_index: attr == NULL\n");
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}

	// handle attribute
	if (IS_ATTR(attr, PID)) {
		lua_pop(L, 2);
		lua_pushinteger(L, (lua_Integer)process_context->pid);
	} else if (IS_ATTR(attr, MMAP_INFO)) {
		lua_pop(L, 1);
		get_mmap_info(L);
	} else if (IS_ATTR(attr, PROCESS_INFO)) {
		lua_pop(L, 1);
		get_process_info(L);
	} else if (IS_ATTR(attr, PTRACE_INFO)) {
		lua_pop(L, 1);
		get_ptrace_info(L);
	} else if (IS_ATTR(attr, SOCKET_CREATE_INFO)) {
		lua_pop(L, 1);
		get_socket_create_info(L);
	} else if (IS_ATTR(attr, TCP_CONNECTION_INFO)) {
		lua_pop(L, 1);
		get_tcp_connection_info(L);
	} else if (IS_ATTR(attr, MODULE_LOAD_INFO)) {
		lua_pop(L, 1);
		get_module_load_info(L);
	} else if (IS_ATTR(attr, MODPROBE_OVERWRITE_INFO)) {
		lua_pop(L, 1);
		get_modprobe_overwrite_info(L);
	} else if (IS_ATTR(attr, PROCESS_LPE_INFO)) {
		lua_pop(L, 1);
		get_process_lpe_info(L);
	} else {
		fprintf(stderr, "process_index: unknown attribute\n");
		lua_pop(L, 2);
		lua_pushnil(L);
	}
	return 1;
}

/**
 * @brief Get the global pid object from the pid list.
 * if pid does not exists in the list, it initializes a new pid object.
 * returns nil on error.
 * Stack: [-1, +1]
 * 
 * @param L 
 * @param pid
 * @return number of return values (1)
 */
int get_process_by_pid(lua_State *L)
{
	int pid;
	bool pid_already_exists;
	struct lua_process_context *process_context;

	// git pid argument
	pid = (int)luaL_checkinteger(L, -1);
	if (pid == 0) {
		fprintf(stderr,
			"get_process_by_pid: invalid arg to get_process_by_pid");
		lua_pushnil(L);
	}
	lua_pop(L, 1);
	// stack is reset

	get_global_pid(L, pid);

	// check if pid is already in the list
	if (lua_isnil(L, -1) == 0) {
		ASSERT(lua_isuserdata(L, -1),
		       "get_process_by_pid: pid in global pid list not found");
		pid_already_exists = true;
	} else {
		pid_already_exists = false;
	}

	// if pid already exists, we just get the process context
	if (pid_already_exists) {
		process_context =
			(struct lua_process_context *)lua_touserdata(L, -1);
		ASSERT(process_context != NULL,
		       "get_process_by_pid: process context not found");
		lua_pop(L, 1);
	} else {
		// set REGISTRY[GLOBAL_PID_LIST][pid] = process_context
		lua_pop(L, 1); // remove the nil from the top
		get_global_pid_list(L);
		lua_pushinteger(L, (lua_Integer)pid);
		process_context = (struct lua_process_context *)lua_newuserdata(
			L, sizeof(struct lua_process_context));
		if (process_context == NULL) {
			fprintf(stderr,
				"get_process_by_pid: could not initialize lua_process_context");
			lua_pop(L, 3);
			goto fail;
		}
		ASSERT(lua_isuserdata(L, -1),
		       "get_process_by_pid: process context not found");
		ASSERT((int)lua_tointeger(L, -2) == pid,
		       "get_process_by_pid: process context not found");
		ASSERT(lua_istable(L, -3),
		       "get_process_by_pid: process context not found");
		lua_settable(L, -3);
		lua_pop(L, 1);
	}
	// stack is reset

	// initialize process context
	if (!pid_already_exists) {
		process_context->pid = pid;
		process_context->process_info_arr = NULL;
		process_context->mmap_info_arr = NULL;
		process_context->ptrace_info_arr = NULL;
		process_context->socket_create_info_arr = NULL;
		process_context->tcp_connection_info_arr = NULL;
		process_context->module_load_info_arr = NULL;
		process_context->modprobe_overwrite_info_arr = NULL;
		process_context->process_lpe_info_arr = NULL;
	}

	// sanity checks
	ASSERT(process_context->pid == pid, "");

	// get REGISTRY[GLOBAL_PID_LIST][pid]
	get_global_pid(L, pid);
	ASSERT(lua_isuserdata(L, -1),
	       "get_process_by_pid: process context not found");

	// create new metatable to associate with 'Process Context' object
	luaL_newmetatable(L, PROCESS_METATABLE);
	lua_pushstring(L, "__index");
	lua_pushcfunction(L, process_index);
	lua_settable(L, -3);

	// sanity checks
	ASSERT(lua_istable(L, -1), "");
	ASSERT(lua_isuserdata(L, -2), "");

	// set metatable of process context
	lua_setmetatable(L, -2);

	// make sure we return process_context on top of stack
	ASSERT(lua_isuserdata(L, -1), "");

	// returns the process context user data.
	return 1;

fail:
	// return nil
	lua_pushnil(L);
	return 1;
}

/**
 * @brief get_stdout_by_stdin. returns next stdin, event_id, filename
 * Stack: [-1, +3]
 * 
 * @param L 
 * @param event_id
 * @return number of return values (1)
 */
int get_stdout_by_stdin(lua_State *L)
{
	int stdin_inode;
	int stdin_type;
	int event_id;
	char std[64];
	int filename_len;
	char *filename = NULL;
	struct lua_db *db;
	int err;

	// git stdin inode argument
	stdin_inode = (int)luaL_checkinteger(L, -1);
	if (stdin_inode == 0) {
		fprintf(stderr,
			"get_stdout_by_stdin: invalid arg to get_stdout_by_stdin");
		lua_pushnil(L);
	}
	lua_pop(L, 1);
	// stack is reset

	db = get_lua_db(L);
	ASSERT(db != NULL, "get_stdout_by_stdin: db not found");

	// get next stdin, event_id, filename
	err = select_stdout_by_stdin(db->db, db->sqlite_stmts, &stdin_inode,
				     &stdin_type, &event_id, &filename,
				     &filename_len);
	if (err == CODE_FAILED) {
		lua_pushnil(L);
		lua_pushnil(L);
		lua_pushnil(L);

		goto out;
	}

	// push stdin, event_id, filename
	if (stdin_type == STD_SOCK) {
		sprintf(std, "socket-%d", stdin_inode);
		lua_pushstring(L, std);
	} else if (stdin_type == STD_PIPE) {
		sprintf(std, "pipe-%d", stdin_inode);
		lua_pushstring(L, std);
	} else if (stdin_type == STD_TTY) {
		sprintf(std, "tty-%d", stdin_inode);
		lua_pushstring(L, std);
	} else {
		lua_pushnil(L);
	}
	lua_pushinteger(L, (lua_Integer)event_id);
	lua_pushstring(L, (const char *)filename);

out:
	if (filename != NULL) {
		free(filename);
		filename = NULL;
	}

	return 3;
}

/**
 * @brief get_stdin_by_stdout. returns next stdout, event_id, filename
 * Stack: [-1, +3]
 * 
 * @param L 
 * @param event_id
 * @return number of return values (1)
 */
int get_stdin_by_stdout(lua_State *L)
{
	int stdout_inode;
	int stdout_type;
	int event_id;
	char std[64];
	int filename_len;
	char *filename = NULL;
	struct lua_db *db;
	int err;

	// git stdout inode argument
	stdout_inode = (int)luaL_checkinteger(L, -1);
	if (stdout_inode == 0) {
		fprintf(stderr,
			"get_stdin_by_stdout: invalid arg to get_stdin_by_stdout");
		lua_pushnil(L);
	}
	lua_pop(L, 1);
	// stack is reset

	db = get_lua_db(L);
	ASSERT(db != NULL, "get_stdin_by_stdout: db not found");

	// get next stdin, event_id, filename
	err = select_stdin_by_stdout(db->db, db->sqlite_stmts, &stdout_inode,
				     &stdout_type, &event_id, &filename,
				     &filename_len);
	if (err == CODE_FAILED) {
		lua_pushnil(L);
		lua_pushnil(L);
		lua_pushnil(L);

		goto out;
	}

	// push stdout, event_id, filename
	if (stdout_type == STD_SOCK) {
		sprintf(std, "socket-%d", stdout_inode);
		lua_pushstring(L, std);
	} else if (stdout_type == STD_PIPE) {
		sprintf(std, "pipe-%d", stdout_inode);
		lua_pushstring(L, std);
	} else if (stdout_type == STD_TTY) {
		sprintf(std, "tty-%d", stdout_inode);
		lua_pushstring(L, std);
	} else {
		lua_pushnil(L);
	}
	lua_pushinteger(L, (lua_Integer)event_id);
	lua_pushstring(L, (const char *)filename);

out:
	if (filename != NULL) {
		free(filename);
		filename = NULL;
	}

	return 3;
}

/**
 * @brief Get pid of the process associated with the given event id
 * Stack: [-1, +1]
 * 
 * @param L 
 * @param event_id
 * @return number of return values (1)
 */
int get_pid_by_event_id(lua_State *L)
{
	int pid;
	int event_id;
	struct lua_db *db;

	// git event id argument
	event_id = (int)luaL_checkinteger(L, -1);
	if (event_id == 0) {
		fprintf(stderr,
			"get_process_by_pid: invalid arg to get_pid_by_event_id");
		lua_pushnil(L);
	}
	lua_pop(L, 1);
	// stack is reset

	db = get_lua_db(L);
	ASSERT(db != NULL, "get_pid_by_event_id: db not found");

	pid = select_tgid_by_event_id(db->db, db->sqlite_stmts, event_id);
	if (pid == CODE_FAILED) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, (lua_Integer)pid);
	return 1;
}

/**
 * @brief Initializes the process context by setting global
 * functions, and the global pid list.
 * 
 * @param L 
 */
void init_process_context(lua_State *L)
{
	ASSERT(L != NULL, "init_process_context: L == NULL");

	// expose global get_process_by_pid function
	lua_pushcfunction(L, get_process_by_pid);
	lua_setglobal(L, "get_process_by_pid");

	lua_pushcfunction(L, get_stdin_by_stdout);
	lua_setglobal(L, "get_stdin_by_stdout");

	lua_pushcfunction(L, get_stdout_by_stdin);
	lua_setglobal(L, "get_stdout_by_stdin");

	lua_pushcfunction(L, get_pid_by_event_id);
	lua_setglobal(L, "get_pid_by_event_id");

	// expose global pid list to keep reference of all process contexts
	lua_pushstring(L, GLOBAL_PID_LIST);
	lua_newtable(L);
	lua_settable(L, LUA_REGISTRYINDEX);
}

/**
 * @brief Tears down the process context by removing all processes from
 * the global pid list and freeing the relevant memory.
 * 
 * @param L 
 */
void teardown_process_context(lua_State *L)
{
	struct lua_process_context *process_context;

	ASSERT(L != NULL, "teardown_process_context: L == NULL");

	// get REGISTRY[GLOBAL_PID_LIST]
	lua_pushstring(L, GLOBAL_PID_LIST);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ASSERT(lua_istable(L, -1),
	       "teardown_process_context: global pid list not found");

	// Loop over REGISTRY[GLOBAL_PID_LIST]
	lua_pushnil(L);
	while (lua_next(L, -2) != 0) {
		ASSERT(lua_isuserdata(L, -1),
		       "teardown_process_context: process context not found");
		process_context =
			(struct lua_process_context *)lua_touserdata(L, -1);
		ASSERT(process_context != NULL,
		       "teardown_process_context: process context is NULL");

		// delete all lua_*info_arrays
		delete_lua_process_info_array(
			process_context->process_info_arr);
		delete_lua_mmap_info_array(process_context->mmap_info_arr);
		delete_lua_ptrace_info_array(process_context->ptrace_info_arr);
		delete_lua_socket_create_info_array(
			process_context->socket_create_info_arr);
		delete_lua_tcp_connection_info_array(
			process_context->tcp_connection_info_arr);
		delete_lua_module_load_info_array(
			process_context->module_load_info_arr);
		delete_lua_modprobe_overwrite_info_array(
			process_context->modprobe_overwrite_info_arr);
		delete_lua_process_lpe_info_array(
			process_context->process_lpe_info_arr);

		lua_pop(L, 1);
	}

	// reset the stack
	lua_settop(L, 0);

	return;
}
