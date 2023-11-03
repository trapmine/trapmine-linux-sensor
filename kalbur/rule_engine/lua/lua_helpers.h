#ifndef LUA_HELPERS_H
#define LUA_HELPERS_H

#include <stdlib.h>
#include <stdio.h>
#include <lua.h>
#include <hash.h>
#include <sqlite3.h>

#include "database.h"
#include "err.h"

#define GLOBAL_LUA_DB "SENSOR_DB"
#define GLOBAL_RULE_ID "SENSOR_LUA_RULE_ID"
#define VARIABLE_VALS_CHUNK_SIZE 10

struct lua_db {
	sqlite3 *db;
	hashtable_t *sqlite_stmts;
};

struct lua_variable_val {
	char *val;
};

typedef struct lua_variable_vals_array {
	int max_size;
	int size;
	struct lua_variable_val **values;
} lua_variable_vals_array;

int get_variables(lua_State *L);

struct lua_db *get_lua_db(lua_State *L);
int get_rule_id(lua_State *L);

void init_helpers(lua_State *L, sqlite3 *db, hashtable_t *sqlite_stmts);
void setup_rule_context(lua_State *L, char *rule_name);
void teardown_helpers(lua_State *L);

#endif // LUA_HELPERS_H