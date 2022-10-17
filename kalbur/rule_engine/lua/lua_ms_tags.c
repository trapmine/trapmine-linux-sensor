#include <err.h>
#include <message.h>
#include <lauxlib.h>
#include "lua_event.h"
#include "lua_ms_tags.h"

static void tag(lua_State *L, int indx, unsigned long tag)
{
	ASSERT(L != NULL, "tag_HLProcBin: L == NULL");
	int err;
	struct message_state *ms;

	lua_getglobal(L, EVENT_GLOBAL);
	err = lua_isuserdata(L, -1);
	if (err != 1) {
		luaL_error(L, "Could not get global 'Event'\n");
		return;
	}

	struct lua_event *event = (struct lua_event *)lua_touserdata(L, -1);
	if (event == NULL) {
		luaL_error(L, "'Event' userdata cannot be NULL");
		return;
	}

	ms = (struct message_state *)event->ms;
	if (ms == NULL) {
		luaL_error(
			L,
			"Unexpected value of 'ms' field of userdata 'Event'. ms == NULL");
		return;
	}

	tag_ms(ms, indx, tag);
}

#define TAG_HLPROCBIN 1UL
static int tag_HLProcBin(lua_State *L)
{
	tag(L, TAG_HL_INDX, TAG_HLPROCBIN);
	return 0;
}

#define TAG_HLFILE 1UL << 1
static int tag_HLFile(lua_State *L)
{
	tag(L, TAG_HL_INDX, TAG_HLFILE);
	return 0;
}

#define TAG_KILL_PROCESS 1UL
static int tag_kill_process(lua_State *L)
{
	tag(L, TAG_KILL_PROCESS_INDX, TAG_KILL_PROCESS);
	return 0;
}

static int tag_Alert(lua_State *L)
{
	int err;
	err = lua_isinteger(L, -1);
	if (err != 1) {
		luaL_error(
			L,
			"Unexpected first argument for 'Alert'. Expected an interger\n");
		return 0;
	}

	unsigned long alert = (unsigned long)lua_tointeger(L, -1);

	tag(L, TAG_ALERT_INDX, alert);

	return 0;
}

static void initialize_tag_funcs(lua_State *L)
{
	ASSERT(L != NULL, "initialize_tag_funcs: L == NULL");

	lua_pushcfunction(L, tag_HLFile);
	lua_setglobal(L, "TagHLFile");

	lua_pushcfunction(L, tag_HLProcBin);
	lua_setglobal(L, "TagHLProcBin");

	lua_pushcfunction(L, tag_Alert);
	lua_setglobal(L, "TagAlert");

	lua_pushcfunction(L, tag_kill_process);
	lua_setglobal(L, "TagKillProcess");
}

#define ALERT_FILELESS_EXEC 1UL
#define ALERT_REVERSE_SHELL 2UL
#define ALERT_LPE_ATTEMPT 3UL
#define ALERT_PROCESS_INJECTION_PTRACE 4UL
#define ALERT_ILLEGITIMATE_SHELL 5UL
#define ALERT_KERNEL_MODULE_LOADED 6UL
#define ALERT_MODPROBE_OVERWRITE 7UL
#define ALERT_PTRACE_ANTIDEBUGGING 8UL
static void initialize_tag_globals(lua_State *L)
{
	ASSERT(L != NULL, "initialize_tag_globals: L == NULL");

	lua_pushinteger(L, ALERT_FILELESS_EXEC);
	lua_setglobal(L, "AlertFilelessExec");

	lua_pushinteger(L, ALERT_REVERSE_SHELL);
	lua_setglobal(L, "AlertReverseShell");

	lua_pushinteger(L, ALERT_LPE_ATTEMPT);
	lua_setglobal(L, "AlertLPEAttempt");

	lua_pushinteger(L, ALERT_PROCESS_INJECTION_PTRACE);
	lua_setglobal(L, "AlertProcessInjectionPtrace");

	lua_pushinteger(L, ALERT_ILLEGITIMATE_SHELL);
	lua_setglobal(L, "AlertIllegitimateShell");

	lua_pushinteger(L, ALERT_PTRACE_ANTIDEBUGGING);
	lua_setglobal(L, "AlertPtraceAntiDebugging");

	lua_pushinteger(L, ALERT_KERNEL_MODULE_LOADED);
	lua_setglobal(L, "AlertKernelModuleLoaded");

	lua_pushinteger(L, ALERT_MODPROBE_OVERWRITE);
	lua_setglobal(L, "AlertModprobeOverwrite");
}

int initialize_tags(lua_State *L)
{
	ASSERT(L != NULL, "initialize_tags: L == NULL");

	initialize_tag_funcs(L);
	initialize_tag_globals(L);

	return CODE_SUCCESS;
}
