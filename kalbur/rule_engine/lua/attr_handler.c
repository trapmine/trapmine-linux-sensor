#include <syscall_defs.h>
#include <lua.h>
#include <err.h>
#include <string.h>
#include "attr_handler.h"

#define TGID_PID "tgidPid"
#define EVENT_TIME "eventTime"
#define COMM "processName"
#define SYSCALL "syscall"

static void push_exit_attr(lua_State *L, const char *attr_name, void *event_obj)
{
	struct exit_event *e = (struct exit_event *)event_obj;

	ASSERT(IS_EXIT_EVENT(e->eh.syscall_nr),
	       "push_exit_attr: incorrect function called. event not exit");

	if (strncmp(attr_name, TGID_PID, sizeof(TGID_PID)) == 0) {
		lua_pushinteger(L, e->eh.tgid_pid);
	} else if (strncmp(attr_name, EVENT_TIME, sizeof(EVENT_TIME)) == 0) {
		lua_pushinteger(L, e->eh.event_time);
	} else if (strncmp(attr_name, COMM, sizeof(COMM)) == 0) {
		lua_pushstring(L, e->eh.comm);
	} else if (strncmp(attr_name, SYSCALL, sizeof(SYSCALL)) == 0) {
		lua_pushinteger(L, e->eh.syscall_nr);
	} else {
		lua_pushnil(L);
	}
}

push_attr_fn get_push_attr_fn(int syscall)
{
	if (IS_EXIT_EVENT(syscall)) {
		return push_exit_attr;
	}

	return NULL;
}

