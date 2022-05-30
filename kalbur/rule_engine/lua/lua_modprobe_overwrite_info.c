#include "lua_modprobe_overwrite_info.h"

/**
 * @brief Frees lua_modprobe_overwrite_info
 * 
 * @param event_info 
 */
void delete_lua_modprobe_overwrite_info(
	struct lua_modprobe_overwrite_info *modprobe_overwrite_info)
{
	if (modprobe_overwrite_info == NULL) {
		return;
	}

	if (modprobe_overwrite_info->event_info != NULL) {
		delete_lua_event_info(modprobe_overwrite_info->event_info);
	}

	if (modprobe_overwrite_info->new_modprobe_path != NULL) {
		free(modprobe_overwrite_info->new_modprobe_path);
		modprobe_overwrite_info->new_modprobe_path = NULL;
	}

	free(modprobe_overwrite_info);
	modprobe_overwrite_info = NULL;
}

/**
 * @brief Frees lua_modprobe_overwrite_info_array
 * 
 * @param event_info 
 */
void delete_lua_modprobe_overwrite_info_array(
	struct lua_modprobe_overwrite_info_array *arr)
{
	if (arr == NULL) {
		return;
	}

	if (arr->size > 0) {
		for (int i = 0; i < arr->size; i++) {
			delete_lua_modprobe_overwrite_info(arr->values[i]);
		}
	}

	arr->size = 0;
	free(arr->values);
	arr->values = NULL;

	free(arr);
	arr = NULL;
}

/**
 * @brief handle index access of modprobe_overwrite_info
 * Expects stack to have string attribute at the top
 * and modprobe_overwrite_info user data at position -2.
 * returns nil if error occurs.
 * 
 * Stack: [-2, +1]
 * @param L
 * @return number of return values (1)
 */
int modprobe_overwrite_info_index(lua_State *L)
{
	struct lua_modprobe_overwrite_info *modprobe_overwrite_info;
	const char *attribute;

	ASSERT(lua_isuserdata(L, -2),
	       "modprobe_overwrite_info_index: stack[-2] not userdata");

	// make sure that the attribute is string
	if (!lua_isstring(L, -1)) {
		fprintf(stderr,
			"modprobe_overwrite_info_index: stack[-1] not string\n");
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}

	// get modprobe_overwrite_info light user data
	lua_getuservalue(L, -2);
	lua_pushstring(L, MODPROBE_OVERWRITE_INFO);
	lua_gettable(L, -2);
	ASSERT(lua_isuserdata(L, -1),
	       "modprobe_overwrite_info_index: modprobe_overwrite_info user value not found");

	modprobe_overwrite_info =
		(struct lua_modprobe_overwrite_info *)lua_touserdata(L, -1);
	ASSERT(modprobe_overwrite_info != NULL,
	       "modprobe_overwrite_info_index: modprobe_overwrite_info is NULL");

	lua_pop(L, 2);

	// get string attribute
	attribute = lua_tostring(L, -1);

	// swap attribute and modprobe_overwrite_info user data
	lua_rotate(L, -2, 1);
	lua_pop(L, 1);

	// handle attribute
	if (IS_ATTR(attribute, EVENT_TIME)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)modprobe_overwrite_info
					   ->event_info->event_time);
		return 1;
	} else if (IS_ATTR(attribute, SYSCALL)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)modprobe_overwrite_info
					   ->event_info->syscall);
		return 1;
	} else if (IS_ATTR(attribute, PROCESS_NAME)) {
		lua_pop(L, 1);
		lua_pushstring(
			L, modprobe_overwrite_info->event_info->process_name);
		return 1;
	} else if (IS_ATTR(attribute, NEW_MODPROBE_PATH_ATTR)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)modprobe_overwrite_info
					   ->new_modprobe_path);
		return 1;
	} else {
		fprintf(stderr,
			"modprobe_overwrite_info_index: invalid attribute: %s\n",
			attribute);
		lua_pop(L, 1);
		lua_pushnil(L);
		return 1;
	}
}

/**
 * @brief handle index access of modprobe_overwrite_info_arr
 * Expects stack to have integer attribute at the top
 * and proces_context user data at position -2.
 * returns nil if error occurs.
 * Stack: [-2, +1]
 * 
 * @param L 
 * @return Number of return values (1)
 */
int modprobe_overwrite_info_arr_index(lua_State *L)
{
	struct lua_modprobe_overwrite_info_array *modprobe_overwrite_info_arr;
	struct lua_modprobe_overwrite_info *modprobe_overwrite_info;
	int index;

	if (!lua_isinteger(L, -1)) {
		fprintf(stderr,
			"modprobe_overwrite_info_arr_index: stack[-1] not integer\n");
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}

	// get the integer index
	index = (int)lua_tointeger(L, -1);
	ASSERT(lua_isuserdata(L, -2),
	       "modprobe_overwrite_info_arr_index: stack[-2] not userdata");

	// get modprobe_overwrite_info_arr_full_ud.userdata["MODPROBE_OVERWRITE_INFO_ARR"]
	// which is the light ud
	lua_getuservalue(L, -2);
	ASSERT(lua_istable(L, -1),
	       "modprobe_overwrite_info_arr_index: stack[-1] not table");
	lua_pushstring(L, MODPROBE_OVERWRITE_INFO_ARR);
	lua_gettable(L, -2);

	modprobe_overwrite_info_arr =
		(struct lua_modprobe_overwrite_info_array *)lua_touserdata(L,
									   -1);
	ASSERT(modprobe_overwrite_info_arr != NULL,
	       "modprobe_overwrite_info_arr_index: modprobe_overwrite_info_arr == NULL");

	lua_pop(L, 4);
	// stack is reset

	if (index <= 0 || index > modprobe_overwrite_info_arr->size) {
		lua_pushnil(L);
	} else {
		modprobe_overwrite_info =
			modprobe_overwrite_info_arr->values[index - 1];
		lua_newuserdata(L, sizeof(struct lua_modprobe_overwrite_info));

		// stores modprobe_overwrite_info (light user data) in a table as user value
		// modprobe_overwrite_info_full_ud.userdata["MODPROBE_OVERWRITE_INFO"] = modprobe_overwrite_info_light_ud
		lua_newtable(L);
		lua_pushstring(L, MODPROBE_OVERWRITE_INFO);
		lua_pushlightuserdata(L, modprobe_overwrite_info);
		lua_settable(L, -3);

		lua_setuservalue(L, -2);

		// create metatable and set some metamethods
		luaL_newmetatable(L, MODPROBE_OVERWRITE_INFO_METATABLE);

		lua_pushstring(L, "__index");
		lua_pushcfunction(L, modprobe_overwrite_info_index);
		lua_settable(L, -3);

		// sanity checks
		ASSERT(lua_istable(L, -1), "");
		ASSERT(lua_isuserdata(L, -2), "");

		// set metatable of process context
		lua_setmetatable(L, -2);

		// make sure that we return modprobe_overwrite_info user data
		ASSERT(lua_isuserdata(L, -1),
		       "modprobe_overwrite_info_arr_index: stack[-1] not userdata");
	}

	return 1;
}

/**
 * @brief Get the modprobe_overwrite_info array length
 * Expects the modprobe_overwrite_info_array userdata on the top of the stack
 * Stack: [-1, +1]
 * 
 * @param L The lua state
 * @return Number of return values (1)
 */
int modprobe_overwrite_info_arr_len(lua_State *L)
{
	struct lua_modprobe_overwrite_info_array *modprobe_overwrite_info_arr;

	ASSERT(lua_isuserdata(L, -1),
	       "modprobe_overwrite_info_arr_len: stack[-2] not userdata");

	// get modprobe_overwrite_info_arr_full_ud.userdata["MODPROBE_OVERWRITE_INFO_ARR"]
	// which is the light ud
	lua_getuservalue(L, -1);
	ASSERT(lua_istable(L, -1),
	       "modprobe_overwrite_info_arr_len: stack[-1] not table");
	lua_pushstring(L, MODPROBE_OVERWRITE_INFO_ARR);
	lua_gettable(L, -2);

	modprobe_overwrite_info_arr =
		(struct lua_modprobe_overwrite_info_array *)lua_touserdata(L,
									   -1);
	ASSERT(modprobe_overwrite_info_arr != NULL,
	       "modprobe_overwrite_info_arr_len: modprobe_overwrite_info_arr == NULL");

	lua_pop(L, 3);
	// stack is reset

	// return the size of the modprobe_overwrite_info_arr
	lua_pushinteger(L, (lua_Integer)modprobe_overwrite_info_arr->size);

	return 1;
}

/**
 * @brief Get the modprobe_overwrite_info object, initialize it, populate data from db.
 * Stack: [-1, +1]
 * 
 * @param L The lua state.
 */
void get_modprobe_overwrite_info(lua_State *L)
{
	struct lua_process_context *process_context;
	struct lua_modprobe_overwrite_info_array *modprobe_overwrite_info_arr;
	struct lua_db *db;

	process_context = (struct lua_process_context *)lua_touserdata(L, -1);
	if (process_context == NULL) {
		fprintf(stderr,
			"get_modprobe_overwrite_info: process_context == NULL\n");
		lua_pop(L, 1);
		lua_pushnil(L);
		return;
	}

	if (process_context->modprobe_overwrite_info_arr != NULL) {
		modprobe_overwrite_info_arr =
			process_context->modprobe_overwrite_info_arr;
	} else {
		modprobe_overwrite_info_arr =
			(struct lua_modprobe_overwrite_info_array *)malloc(
				sizeof(struct lua_modprobe_overwrite_info_array));
		modprobe_overwrite_info_arr->max_size =
			MODPROBE_OVERWRITE_INFO_CHUNK_SIZE;
		modprobe_overwrite_info_arr->size = 0;
		modprobe_overwrite_info_arr->values =
			(struct lua_modprobe_overwrite_info **)malloc(
				sizeof(struct lua_modprobe_overwrite_info *) *
				(size_t)modprobe_overwrite_info_arr->max_size);

		db = get_lua_db(L);

		select_all_modprobe_overwrite_info(db->db, db->sqlite_stmts,
						   modprobe_overwrite_info_arr,
						   process_context->pid);
		process_context->modprobe_overwrite_info_arr =
			modprobe_overwrite_info_arr;
	}

	lua_pop(L, 1);
	// stack is reset

	lua_newuserdata(L, sizeof(struct lua_modprobe_overwrite_info_array));

	// stores modprobe_overwrite_info_arr (light user data) in a table as user value
	// modprobe_overwrite_info_arr_full_ud.userdata["MODPROBE_OVERWRITE_INFO_ARR"] = modprobe_overwrite_info_arr_light_ud
	lua_newtable(L);
	lua_pushstring(L, MODPROBE_OVERWRITE_INFO_ARR);
	lua_pushlightuserdata(L, modprobe_overwrite_info_arr);
	lua_settable(L, -3);
	lua_setuservalue(L, -2);

	// create metatable and set some metamethods
	luaL_newmetatable(L, MODPROBE_OVERWRITE_INFO_ARR_METATABLE);

	lua_pushstring(L, "__index");
	lua_pushcfunction(L, modprobe_overwrite_info_arr_index);
	lua_settable(L, -3);

	lua_pushstring(L, "__len");
	lua_pushcfunction(L, modprobe_overwrite_info_arr_len);
	lua_settable(L, -3);

	// sanity checks
	ASSERT(lua_istable(L, -1), "");
	ASSERT(lua_isuserdata(L, -2), "");

	lua_setmetatable(L, -2);

	// make sure we return the modprobe_overwrite_info_arr
	ASSERT(lua_isuserdata(L, -1), "");
}
