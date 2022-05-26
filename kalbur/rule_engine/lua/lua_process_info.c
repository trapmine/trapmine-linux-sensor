#include "lua_process_info.h"

/**
 * @brief Frees lua_process_info
 * 
 * @param event_info 
 */
void delete_lua_process_info(struct lua_process_info *process_info)
{
	if (process_info == NULL) {
		return;
	}

	if (process_info->event_info != NULL) {
		delete_lua_event_info(process_info->event_info);
	}

	if (process_info->args != NULL) {
		free(process_info->args);
		process_info->args = NULL;
	}

	if (process_info->env != NULL) {
		free(process_info->env);
		process_info->env = NULL;
	}

	if (process_info->interpreter != NULL) {
		free(process_info->interpreter);
		process_info->interpreter = NULL;
	}

	if (process_info->file_info != NULL) {
		delete_lua_file_info(process_info->file_info);
	}

	free(process_info);
	process_info = NULL;
}

/**
 * @brief Frees lua_process_info_array
 * 
 * @param event_info 
 */
void delete_lua_process_info_array(struct lua_process_info_array *arr)
{
	if (arr == NULL) {
		return;
	}

	if (arr->size > 0) {
		for (int i = 0; i < arr->size; i++) {
			delete_lua_process_info(arr->values[i]);
		}
	}

	arr->size = 0;
	free(arr->values);
	arr->values = NULL;

	free(arr);
	arr = NULL;
}

/**
 * @brief handle index access of process_info
 * Expects stack to have string attribute at the top
 * and process_info user data at position -2.
 * returns nil if error occurs.
 * 
 * Stack: [-2, +1]
 * @param L
 * @return number of return values (1)
 */
int process_info_index(lua_State *L)
{
	struct lua_process_info *process_info;
	const char *attribute;

	ASSERT(lua_isuserdata(L, -2),
	       "process_info_index: stack[-2] not userdata");

	// make sure that the attribute is string
	if (!lua_isstring(L, -1)) {
		fprintf(stderr, "process_info_index: stack[-1] not string\n");
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}

	// get process_info light user data
	lua_getuservalue(L, -2);
	lua_pushstring(L, PROCESS_INFO);
	lua_gettable(L, -2);
	ASSERT(lua_isuserdata(L, -1),
	       "process_info_index: process_info user value not found");

	process_info = (struct lua_process_info *)lua_touserdata(L, -1);
	ASSERT(process_info != NULL,
	       "process_info_index: process_info is NULL");

	lua_pop(L, 2);

	// get string attribute
	attribute = lua_tostring(L, -1);

	// swap attribute and process_info user data
	lua_rotate(L, -2, 1);
	lua_pop(L, 1);

	// handle attribute
	if (IS_ATTR(attribute, EVENT_TIME)) {
		lua_pop(L, 1);
		lua_pushinteger(
			L, (lua_Integer)process_info->event_info->event_time);
		return 1;
	} else if (IS_ATTR(attribute, SYSCALL)) {
		lua_pop(L, 1);
		lua_pushinteger(L,
				(lua_Integer)process_info->event_info->syscall);
		return 1;
	} else if (IS_ATTR(attribute, PROCESS_NAME)) {
		lua_pop(L, 1);
		lua_pushstring(L, process_info->event_info->process_name);
		return 1;
	} else if (IS_ATTR(attribute, PARENT_PID_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->parent_tgid);
		return 1;
	} else if (IS_ATTR(attribute, CLONE_FLAGS_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->clone_flags);
		return 1;
	} else if (IS_ATTR(attribute, ARGS_ATTR)) {
		lua_pop(L, 1);
		lua_pushstring(L, (const char *)process_info->args);
		return 1;
	} else if (IS_ATTR(attribute, ENV_ATTR)) {
		lua_pop(L, 1);
		lua_pushstring(L, (const char *)process_info->env);
		return 1;
	} else if (IS_ATTR(attribute, INTERPRETER_ATTR)) {
		lua_pop(L, 1);
		lua_pushstring(L, (const char *)process_info->interpreter);
		return 1;
	} else if (IS_ATTR(attribute, UID_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->uid);
		return 1;
	} else if (IS_ATTR(attribute, GID_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->gid);
		return 1;
	} else if (IS_ATTR(attribute, EUID_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->euid);
		return 1;
	} else if (IS_ATTR(attribute, EGID_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->egid);
		return 1;
	} else if (IS_ATTR(attribute, STDIN_INODE_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->stdin_inode);
		return 1;
	} else if (IS_ATTR(attribute, STDOUT_INODE_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->stdout_inode);
		return 1;
	} else if (IS_ATTR(attribute, STDERR_INODE_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->stderr_inode);
		return 1;
	} else if (IS_ATTR(attribute, STDIN_TYPE_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->stdin_type);
		return 1;
	} else if (IS_ATTR(attribute, STDOUT_TYPE_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->stdout_type);
		return 1;
	} else if (IS_ATTR(attribute, STDERR_TYPE_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)process_info->stderr_type);
		return 1;
	} else if (IS_ATTR(attribute, FILE)) {
		lua_pop(L, 1);
		// stack is reset

		lua_newuserdata(L, sizeof(struct lua_file_info));

		// stores file_info (light user data) in a table as user value
		// file_info_full_ud.userdata["FILE_INFO"] = file_info_light_ud
		lua_newtable(L);
		lua_pushstring(L, FILE_INFO);
		lua_pushlightuserdata(L, process_info->file_info);
		lua_settable(L, -3);

		lua_setuservalue(L, -2);

		// create new metatable and set its metamethods
		luaL_newmetatable(L, FILE_INFO_METATABLE);

		lua_pushstring(L, "__index");
		lua_pushcfunction(L, file_info_index);
		lua_settable(L, -3);

		// sanity checks
		ASSERT(lua_istable(L, -1), "");
		ASSERT(lua_isuserdata(L, -2), "");

		// set metatable of process context
		lua_setmetatable(L, -2);

		// make sure that we return file_info userdata
		ASSERT(lua_isuserdata(L, -1), "");

		return 1;
	} else {
		fprintf(stderr, "process_info_index: invalid attribute: %s\n",
			attribute);
		lua_pop(L, 1);
		lua_pushnil(L);
		return 1;
	}
}

/**
 * @brief handle index access of process_info_arr
 * Expects stack to have integer attribute at the top
 * and proces_context user data at position -2.
 * returns nil if error occurs.
 * Stack: [-2, +1]
 * 
 * @param L 
 * @return Number of return values (1)
 */
int process_info_arr_index(lua_State *L)
{
	struct lua_process_info_array *process_info_arr;
	struct lua_process_info *process_info;
	int index;

	if (!lua_isinteger(L, -1)) {
		fprintf(stderr,
			"process_info_arr_index: stack[-1] not integer\n");
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}

	// get the integer index
	index = (int)lua_tointeger(L, -1);
	ASSERT(lua_isuserdata(L, -2),
	       "process_info_arr_index: stack[-2] not userdata");

	// get process_info_arr_full_ud.userdata["PROCESS_INFO_ARR"]
	// which is the light ud
	lua_getuservalue(L, -2);
	ASSERT(lua_istable(L, -1),
	       "process_info_arr_index: stack[-1] not table");
	lua_pushstring(L, PROCESS_INFO_ARR);
	lua_gettable(L, -2);

	process_info_arr =
		(struct lua_process_info_array *)lua_touserdata(L, -1);
	ASSERT(process_info_arr != NULL,
	       "process_info_arr_index: process_info_arr == NULL");

	lua_pop(L, 4);
	// stack is reset

	if (index <= 0 || index > process_info_arr->size) {
		lua_pushnil(L);
	} else {
		process_info = process_info_arr->values[index - 1];
		lua_newuserdata(L, sizeof(struct lua_process_info));

		// stores process_info (light user data) in a table as user value
		// process_info_full_ud.userdata["PROCESS_INFO"] = process_info_light_ud
		lua_newtable(L);
		lua_pushstring(L, PROCESS_INFO);
		lua_pushlightuserdata(L, process_info);
		lua_settable(L, -3);

		lua_setuservalue(L, -2);

		// create metatable and set some metamethods
		luaL_newmetatable(L, PROCESS_INFO_METATABLE);

		lua_pushstring(L, "__index");
		lua_pushcfunction(L, process_info_index);
		lua_settable(L, -3);

		// sanity checks
		ASSERT(lua_istable(L, -1), "");
		ASSERT(lua_isuserdata(L, -2), "");

		// set metatable of process context
		lua_setmetatable(L, -2);

		// make sure that we return process_info user data
		ASSERT(lua_isuserdata(L, -1),
		       "process_info_arr_index: stack[-1] not userdata");
	}

	return 1;
}

/**
 * @brief Get the process_info array length
 * Expects the process_info_array userdata on the top of the stack
 * Stack: [-1, +1]
 * 
 * @param L The lua state
 * @return Number of return values (1)
 */
int process_info_arr_len(lua_State *L)
{
	struct lua_process_info_array *process_info_arr;

	ASSERT(lua_isuserdata(L, -1),
	       "process_info_arr_len: stack[-2] not userdata");

	// get process_info_arr_full_ud.userdata["PROCESS_INFO_ARR"]
	// which is the light ud
	lua_getuservalue(L, -1);
	ASSERT(lua_istable(L, -1), "process_info_arr_len: stack[-1] not table");
	lua_pushstring(L, PROCESS_INFO_ARR);
	lua_gettable(L, -2);

	process_info_arr =
		(struct lua_process_info_array *)lua_touserdata(L, -1);
	ASSERT(process_info_arr != NULL,
	       "process_info_arr_len: process_info_arr == NULL");

	lua_pop(L, 3);
	// stack is reset

	// return the size of the process_info_arr
	lua_pushinteger(L, (lua_Integer)process_info_arr->size);

	return 1;
}

/**
 * @brief Get the process_info object, initialize it, populate data from db.
 * Stack: [-1, +1]
 * 
 * @param L The lua state.
 */
void get_process_info(lua_State *L)
{
	struct lua_process_context *process_context;
	struct lua_process_info_array *process_info_arr;
	struct lua_db *db;

	process_context = (struct lua_process_context *)lua_touserdata(L, -1);
	if (process_context == NULL) {
		fprintf(stderr, "get_process_info: process_context == NULL\n");
		lua_pop(L, 1);
		lua_pushnil(L);
		return;
	}

	if (process_context->process_info_arr != NULL) {
		process_info_arr = process_context->process_info_arr;
	} else {
		process_info_arr = (struct lua_process_info_array *)malloc(
			sizeof(struct lua_process_info_array));
		process_info_arr->max_size = PROCESS_INFO_CHUNK_SIZE;
		process_info_arr->size = 0;
		process_info_arr->values = (struct lua_process_info **)malloc(
			sizeof(struct lua_process_info *) *
			(size_t)process_info_arr->max_size);

		db = get_lua_db(L);

		select_all_process_info(db->db, db->sqlite_stmts,
					process_info_arr, process_context->pid);
		process_context->process_info_arr = process_info_arr;
	}

	lua_pop(L, 1);
	// stack is reset

	lua_newuserdata(L, sizeof(struct lua_process_info_array));

	// stores process_info_arr (light user data) in a table as user value
	// process_info_arr_full_ud.userdata["PROCESS_INFO_ARR"] = process_info_arr_light_ud
	lua_newtable(L);
	lua_pushstring(L, PROCESS_INFO_ARR);
	lua_pushlightuserdata(L, process_info_arr);
	lua_settable(L, -3);
	lua_setuservalue(L, -2);

	// create metatable and set some metamethods
	luaL_newmetatable(L, PROCESS_INFO_ARR_METATABLE);

	lua_pushstring(L, "__index");
	lua_pushcfunction(L, process_info_arr_index);
	lua_settable(L, -3);

	lua_pushstring(L, "__len");
	lua_pushcfunction(L, process_info_arr_len);
	lua_settable(L, -3);

	// sanity checks
	ASSERT(lua_istable(L, -1), "");
	ASSERT(lua_isuserdata(L, -2), "");

	lua_setmetatable(L, -2);

	// make sure we return the process_info_arr
	ASSERT(lua_isuserdata(L, -1), "");
}
