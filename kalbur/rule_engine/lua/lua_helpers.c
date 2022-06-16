#include "lua_helpers.h"


/**
 * @brief Get the global lua db object
 * Stack: [-0, +0]
 * 
 * @param L The lua state.
 *
 * @return A pointer to the lua_db object
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
 * @brief Initializes the helper functions by setting up lua_db, global
 * functions.
 * 
 * @param L 
 */
void init_helpers(lua_State *L, sqlite3 *db, hashtable_t *sqlite_stmts)
{
	struct lua_db *lua_db;

	ASSERT(L != NULL, "init_helpers: L == NULL");
	ASSERT(db != NULL, "init_helpers: db == NULL");
	ASSERT(sqlite_stmts != NULL, "init_helpers: sqlite_stmts == NULL");

	// initialize lua_db globally and put it in registry.
	lua_pushstring(L, GLOBAL_LUA_DB);
	lua_db = (struct lua_db *)lua_newuserdata(L, sizeof(struct lua_db));
	if (lua_db == NULL) {
		fprintf(stderr, "init_helpers: could not initialize lua_db");
		lua_pop(L, 1);
		return;
	}

	lua_db->db = db;
	lua_db->sqlite_stmts = sqlite_stmts;

	lua_settable(L, LUA_REGISTRYINDEX);

	// expose global get_process_by_pid function
	lua_pushcfunction(L, is_disallowed_parent);
	lua_setglobal(L, "is_disallowed_parent");
}

/**
 * @brief Tears down helpers
 * 
 * @param L 
 */
void teardown_helpers(lua_State *L)
{
	ASSERT(L != NULL, "teardown_helpers: L == NULL");

	// reset the stack
	lua_settop(L, 0);

	return;
}
