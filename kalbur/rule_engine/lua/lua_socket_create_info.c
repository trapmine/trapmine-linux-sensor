#include "lua_socket_create_info.h"

/**
 * @brief Frees lua_socket_create_info
 * 
 * @param event_info 
 */
void delete_lua_socket_create_info(
	struct lua_socket_create_info *socket_create_info)
{
	if (socket_create_info == NULL) {
		return;
	}

	if (socket_create_info->event_info != NULL) {
		delete_lua_event_info(socket_create_info->event_info);
	}

	if (socket_create_info->family != NULL) {
		free(socket_create_info->family);
		socket_create_info->family = NULL;
	}

	if (socket_create_info->socket_type != NULL) {
		free(socket_create_info->socket_type);
		socket_create_info->socket_type = NULL;
	}

	free(socket_create_info);
	socket_create_info = NULL;
}

/**
 * @brief Frees lua_socket_create_info_array
 * 
 * @param event_info 
 */
void delete_lua_socket_create_info_array(
	struct lua_socket_create_info_array *arr)
{
	if (arr == NULL) {
		return;
	}

	if (arr->size > 0) {
		for (int i = 0; i < arr->size; i++) {
			delete_lua_socket_create_info(arr->values[i]);
		}
	}

	arr->size = 0;
	free(arr->values);
	arr->values = NULL;

	free(arr);
	arr = NULL;
}

/**
 * @brief handle index access of socket_create_info
 * Expects stack to have string attribute at the top
 * and socket_create_info user data at position -2.
 * returns nil if error occurs.
 * 
 * Stack: [-2, +1]
 * @param L
 * @return number of return values (1)
 */
int socket_create_info_index(lua_State *L)
{
	struct lua_socket_create_info *socket_create_info;
	const char *attribute;

	ASSERT(lua_isuserdata(L, -2),
	       "socket_create_info_index: stack[-2] not userdata");

	// make sure that the attribute is string
	if (!lua_isstring(L, -1)) {
		fprintf(stderr,
			"socket_create_info_index: stack[-1] not string\n");
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}

	// get socket_create_info light user data
	lua_getuservalue(L, -2);
	lua_pushstring(L, SOCKET_CREATE_INFO);
	lua_gettable(L, -2);
	ASSERT(lua_isuserdata(L, -1),
	       "socket_create_info_index: socket_create_info user value not found");

	socket_create_info =
		(struct lua_socket_create_info *)lua_touserdata(L, -1);
	ASSERT(socket_create_info != NULL,
	       "socket_create_info_index: socket_create_info is NULL");

	lua_pop(L, 2);

	// get string attribute
	attribute = lua_tostring(L, -1);

	// swap attribute and socket_create_info user data
	lua_rotate(L, -2, 1);
	lua_pop(L, 1);

	// handle attribute
	if (IS_ATTR(attribute, EVENT_TIME)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)socket_create_info->event_info
					   ->event_time);
		return 1;
	} else if (IS_ATTR(attribute, SYSCALL)) {
		lua_pop(L, 1);
		lua_pushinteger(
			L,
			(lua_Integer)socket_create_info->event_info->syscall);
		return 1;
	} else if (IS_ATTR(attribute, PROCESS_NAME)) {
		lua_pop(L, 1);
		lua_pushstring(L, socket_create_info->event_info->process_name);
		return 1;
	} else if (IS_ATTR(attribute, INODE_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)socket_create_info->inode);
		return 1;
	} else if (IS_ATTR(attribute, FAMILY_ATTR)) {
		lua_pop(L, 1);
		lua_pushstring(L, socket_create_info->family);
		return 1;
	} else if (IS_ATTR(attribute, SOCKET_TYPE_ATTR)) {
		lua_pop(L, 1);
		lua_pushstring(L, socket_create_info->socket_type);
		return 1;
	} else {
		fprintf(stderr,
			"socket_create_info_index: invalid attribute: %s\n",
			attribute);
		lua_pop(L, 1);
		lua_pushnil(L);
		return 1;
	}
}

/**
 * @brief handle index access of socket_create_info_arr
 * Expects stack to have integer attribute at the top
 * and proces_context user data at position -2.
 * returns nil if error occurs.
 * Stack: [-2, +1]
 * 
 * @param L 
 * @return Number of return values (1)
 */
int socket_create_info_arr_index(lua_State *L)
{
	struct lua_socket_create_info_array *socket_create_info_arr;
	struct lua_socket_create_info *socket_create_info;
	int index;

	if (!lua_isinteger(L, -1)) {
		fprintf(stderr,
			"socket_create_info_arr_index: stack[-1] not integer\n");
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}

	// get the integer index
	index = (int)lua_tointeger(L, -1);
	ASSERT(lua_isuserdata(L, -2),
	       "socket_create_info_arr_index: stack[-2] not userdata");

	// get socket_create_info_arr_full_ud.userdata["SOCKET_CREATE_INFO_ARR"]
	// which is the light ud
	lua_getuservalue(L, -2);
	ASSERT(lua_istable(L, -1),
	       "socket_create_info_arr_index: stack[-1] not table");
	lua_pushstring(L, SOCKET_CREATE_INFO_ARR);
	lua_gettable(L, -2);

	socket_create_info_arr =
		(struct lua_socket_create_info_array *)lua_touserdata(L, -1);
	ASSERT(socket_create_info_arr != NULL,
	       "socket_create_info_arr_index: socket_create_info_arr == NULL");

	lua_pop(L, 4);
	// stack is reset

	if (index <= 0 || index > socket_create_info_arr->size) {
		lua_pushnil(L);
	} else {
		socket_create_info = socket_create_info_arr->values[index - 1];
		lua_newuserdata(L, sizeof(struct lua_socket_create_info));

		// stores socket_create_info (light user data) in a table as user value
		// socket_create_info_full_ud.userdata["SOCKET_CREATE_INFO"] = socket_create_info_light_ud
		lua_newtable(L);
		lua_pushstring(L, SOCKET_CREATE_INFO);
		lua_pushlightuserdata(L, socket_create_info);
		lua_settable(L, -3);

		lua_setuservalue(L, -2);

		// create metatable and set some metamethods
		luaL_newmetatable(L, SOCKET_CREATE_INFO_METATABLE);

		lua_pushstring(L, "__index");
		lua_pushcfunction(L, socket_create_info_index);
		lua_settable(L, -3);

		// sanity checks
		ASSERT(lua_istable(L, -1), "");
		ASSERT(lua_isuserdata(L, -2), "");

		// set metatable of process context
		lua_setmetatable(L, -2);

		// make sure that we return socket_create_info user data
		ASSERT(lua_isuserdata(L, -1),
		       "socket_create_info_arr_index: stack[-1] not userdata");
	}

	return 1;
}

/**
 * @brief Get the socket_create_info array length
 * Expects the socket_create_info_array userdata on the top of the stack
 * Stack: [-1, +1]
 * 
 * @param L The lua state
 * @return Number of return values (1)
 */
int socket_create_info_arr_len(lua_State *L)
{
	struct lua_socket_create_info_array *socket_create_info_arr;

	ASSERT(lua_isuserdata(L, -1),
	       "socket_create_info_arr_len: stack[-2] not userdata");

	// get socket_create_info_arr_full_ud.userdata["SOCKET_CREATE_INFO_ARR"]
	// which is the light ud
	lua_getuservalue(L, -1);
	ASSERT(lua_istable(L, -1),
	       "socket_create_info_arr_len: stack[-1] not table");
	lua_pushstring(L, SOCKET_CREATE_INFO_ARR);
	lua_gettable(L, -2);

	socket_create_info_arr =
		(struct lua_socket_create_info_array *)lua_touserdata(L, -1);
	ASSERT(socket_create_info_arr != NULL,
	       "socket_create_info_arr_len: socket_create_info_arr == NULL");

	lua_pop(L, 3);
	// stack is reset

	// return the size of the socket_create_info_arr
	lua_pushinteger(L, (lua_Integer)socket_create_info_arr->size);

	return 1;
}

/**
 * @brief Get the socket_create_info object, initialize it, populate data from db.
 * Stack: [-1, +1]
 * 
 * @param L The lua state.
 */
void get_socket_create_info(lua_State *L)
{
	struct lua_process_context *process_context;
	struct lua_socket_create_info_array *socket_create_info_arr;
	struct lua_db *db;

	process_context = (struct lua_process_context *)lua_touserdata(L, -1);
	if (process_context == NULL) {
		fprintf(stderr,
			"get_socket_create_info: process_context == NULL\n");
		lua_pop(L, 1);
		lua_pushnil(L);
		return;
	}

	if (process_context->socket_create_info_arr != NULL) {
		socket_create_info_arr =
			process_context->socket_create_info_arr;
	} else {
		socket_create_info_arr =
			(struct lua_socket_create_info_array *)malloc(
				sizeof(struct lua_socket_create_info_array));
		socket_create_info_arr->max_size =
			SOCKET_CREATE_INFO_CHUNK_SIZE;
		socket_create_info_arr->size = 0;
		socket_create_info_arr->values =
			(struct lua_socket_create_info **)malloc(
				sizeof(struct lua_socket_create_info *) *
				(size_t)socket_create_info_arr->max_size);

		db = get_lua_db(L);

		select_all_socket_create_info(db->db, db->sqlite_stmts,
					      socket_create_info_arr,
					      process_context->pid);
		process_context->socket_create_info_arr =
			socket_create_info_arr;
	}

	lua_pop(L, 1);
	// stack is reset

	lua_newuserdata(L, sizeof(struct lua_socket_create_info_array));

	// stores socket_create_info_arr (light user data) in a table as user value
	// socket_create_info_arr_full_ud.userdata["SOCKET_CREATE_INFO_ARR"] = socket_create_info_arr_light_ud
	lua_newtable(L);
	lua_pushstring(L, SOCKET_CREATE_INFO_ARR);
	lua_pushlightuserdata(L, socket_create_info_arr);
	lua_settable(L, -3);
	lua_setuservalue(L, -2);

	// create metatable and set some metamethods
	luaL_newmetatable(L, SOCKET_CREATE_INFO_ARR_METATABLE);

	lua_pushstring(L, "__index");
	lua_pushcfunction(L, socket_create_info_arr_index);
	lua_settable(L, -3);

	lua_pushstring(L, "__len");
	lua_pushcfunction(L, socket_create_info_arr_len);
	lua_settable(L, -3);

	// sanity checks
	ASSERT(lua_istable(L, -1), "");
	ASSERT(lua_isuserdata(L, -2), "");

	lua_setmetatable(L, -2);

	// make sure we return the socket_create_info_arr
	ASSERT(lua_isuserdata(L, -1), "");
}
