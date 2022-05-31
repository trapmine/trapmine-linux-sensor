#include "lua_file_info.h"

/**
 * @brief Frees lua_file_info
 * 
 * @param event_info 
 */
void delete_lua_file_info(struct lua_file_info *file_info)
{
	if (file_info == NULL) {
		return;
	}

	if (file_info->filename != NULL) {
		free(file_info->filename);
		file_info->filename = NULL;
	}

	free(file_info);
	file_info = NULL;
}

/**
 * @brief handle index access of file_info
 * Expects stack to have string attribute at the top
 * and file_info user data at position -2.
 * returns nil if error occurs.
 * 
 * Stack: [-2, +1]
 * @param L
 * @return number of return values (1)
 */
int file_info_index(lua_State *L)
{
	struct lua_file_info *file_info;
	const char *attribute;

	ASSERT(lua_isuserdata(L, -2),
	       "file_info_index: stack[-2] not userdata");

	// make sure that the attribute is string
	if (!lua_isstring(L, -1)) {
		fprintf(stderr, "file_info_index: stack[-1] not string\n");
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}

	// get file_info light user data
	lua_getuservalue(L, -2);
	lua_pushstring(L, FILE_INFO);
	lua_gettable(L, -2);
	ASSERT(lua_isuserdata(L, -1),
	       "file_info_index: file_info user value not found");

	file_info = (struct lua_file_info *)lua_touserdata(L, -1);
	ASSERT(file_info != NULL, "file_info_index: file_info is NULL");

	lua_pop(L, 2);

	// get string attribute
	attribute = lua_tostring(L, -1);

	// swap attribute and file_info user data
	lua_rotate(L, -2, 1);
	lua_pop(L, 2);

	// handle attribute
	if (IS_ATTR(attribute, FILENAME)) {
		lua_pop(L, 1);
		lua_pushstring(L, file_info->filename);
		return 1;
	} else if (IS_ATTR(attribute, INODE)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)file_info->inode);
		return 1;
	}
	if (IS_ATTR(attribute, S_MAGIC)) {
		lua_pop(L, 1);
		lua_pushinteger(L, (lua_Integer)file_info->s_magic);
		return 1;
	} else {
		fprintf(stderr, "file_info_index: invalid attribute: %s\n",
			attribute);
		lua_pop(L, 1);
		lua_pushnil(L);
		return 1;
	}
}
