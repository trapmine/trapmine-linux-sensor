#include "lua_process.h"

/**
 * @brief Get the global lua db object
 * Stack: [-0, +0]
 * 
 * @param L The lua state.
 *
 * @return The length of the mmap_info_arr array.
 */
struct lua_db *get_lua_db(lua_State *L)
{
	struct lua_db *db;

	lua_pushstring(L, GLOBAL_LUA_DB);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ASSERT(lua_isuserdata(L, -1), "get_lua_db: global db conn not found");

	db = (struct lua_db *)lua_touserdata(L, -1);
	ASSERT(db != NULL, "get_lua_db: global db conn not found");
	lua_pop(L, 1);

	return db;
}

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
	}

	// sanity checks
	ASSERT(process_context->pid == pid, "");
	ASSERT(process_context->mmap_info_arr == NULL, "");

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
 * @brief Initializes the process context by setting up lua_db, global
 * functions, and the global pid list.
 * 
 * @param L 
 */
void init_process_context(lua_State *L, sqlite3 *db, hashtable_t *sqlite_stmts)
{
	struct lua_db *lua_db;

	ASSERT(L != NULL, "init_process_context: L == NULL");
	ASSERT(db != NULL, "init_process_context: db == NULL");
	ASSERT(sqlite_stmts != NULL,
	       "init_process_context: sqlite_stmts == NULL");

	// initialize lua_db globally and put it in registry.
	lua_pushstring(L, GLOBAL_LUA_DB);
	lua_db = (struct lua_db *)lua_newuserdata(L, sizeof(struct lua_db));
	if (lua_db == NULL) {
		fprintf(stderr,
			"init_process_context: could not initialize lua_db");
		lua_pop(L, 1);
		return;
	}

	lua_db->db = db;
	lua_db->sqlite_stmts = sqlite_stmts;

	lua_settable(L, LUA_REGISTRYINDEX);

	// expose global get_process_by_pid function
	lua_pushcfunction(L, get_process_by_pid);
	lua_setglobal(L, "get_process_by_pid");

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

		lua_pop(L, 1);
	}

	// reset the stack
	lua_settop(L, 0);

	return;
}
