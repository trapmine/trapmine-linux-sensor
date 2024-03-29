#include "lua_helpers.h"

int get_variables(lua_State *L)
{
	struct lua_db *db;
	const char *variable_key;
	struct lua_variable_vals_array *variable_vals;
	int rule_id;
	int err;

	if (!lua_isstring(L, -1)) {
		fprintf(stderr, "get_variables: stack[-1] not string\n");
		lua_pop(L, 1);
		lua_pushnil(L);
		return 1;
	}

	variable_key = lua_tostring(L, -1);

	variable_vals =
			(struct lua_variable_vals_array *)malloc(
				sizeof(struct lua_variable_vals_array));
		variable_vals->max_size = VARIABLE_VALS_CHUNK_SIZE;
		variable_vals->size = 0;
		variable_vals->values =
			(struct lua_variable_val **)malloc(
				sizeof(struct lua_variable_val *) *
				(size_t)variable_vals->max_size);

	rule_id = get_rule_id(L);
	db = get_lua_db(L);
	err = select_variable_vals(db->db, db->sqlite_stmts, variable_key, rule_id, variable_vals);

	if (err == CODE_FAILED) {
		lua_pop(L, 1);
		lua_pushnil(L);
		return 1;
	}

	lua_pop(L, 1);
	lua_createtable(L, variable_vals->size, 0);

	for(int i = 0; i < variable_vals->size; i++) {
		lua_pushstring(L, variable_vals->values[i]->val);
		lua_rawseti(L, -2, i);
	}

	for(int i = 0; i < variable_vals->size; i++) {
		if(variable_vals->values[i]) {
			if(variable_vals->values[i]->val) {
				free(variable_vals->values[i]->val);
			}
			free(variable_vals->values[i]);
		}
	}

	variable_vals->size = 0;
	variable_vals->max_size = 0;
	free(variable_vals);
	variable_vals = NULL;

	return 1;
}

/**
 * @brief Get the rule id of current lua script from the lua registry
 * Stack: [-0, +0]
 * 
 * @param L The lua state.
 * @return int The rule id of current lua script
 */
int get_rule_id(lua_State *L)
{
	int rule_id;

	lua_pushstring(L, GLOBAL_RULE_ID);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ASSERT(lua_isnumber(L, -1), "get_rule_id: global rule id not found");

	rule_id = (int)lua_tointeger(L, -1);
	ASSERT(rule_id != 0, "get_rule_id: global rule id not found");
	lua_pop(L, 1);

	return rule_id;
}

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
 * @brief Sets the rule id of current lua script to the lua registry
 * If the rule name is of format name scriptname_id.lua, then the id is set
 * otherwise it is set to 0.
 * Stack: [-0, +0]
 * 
 * @param L The lua state.
 * @param rule_name The name of the rule.
*/
void setup_rule_context(lua_State *L, char *rule_name)
{
	int rule_id = 0;
	size_t rule_name_len;
	int id_offset = 0;
	ASSERT(L != NULL, "setup_rule_context: L == NULL");
	ASSERT(rule_name != NULL, "setup_rule_context: rule_name == NULL");

	rule_name_len = strlen(rule_name);
	for(int i = (int)rule_name_len - 1; i >= 0; i--) {
		if(rule_name[i] == '_') {
			id_offset = i + 1;
			break;
		}
	}

	if (id_offset > 0) {
		rule_id = atoi(rule_name + id_offset);
	}

	lua_pushstring(L, GLOBAL_RULE_ID);
	lua_pushinteger(L, (long)rule_id);
	lua_settable(L, LUA_REGISTRYINDEX);
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

	// expose global get_variables function
	lua_pushcfunction(L, get_variables);
	lua_setglobal(L, "get_variables");
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
