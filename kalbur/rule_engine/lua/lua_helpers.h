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

struct lua_db {
	sqlite3 *db;
	hashtable_t *sqlite_stmts;
};


struct lua_db *get_lua_db(lua_State *L);

void init_helpers(lua_State *L, sqlite3 *db, hashtable_t *sqlite_stmts);
void teardown_helpers(lua_State *L);

#endif // LUA_HELPERS_H