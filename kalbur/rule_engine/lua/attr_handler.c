#include <syscall_defs.h>
#include <lua.h>
#include <err.h>
#include <string.h>
#include <helpers.h>
#include "attr_handler.h"

#define TGID_PID "tgidPid"
#define EVENT_TIME "eventTime"
#define COMM "processName"
#define SYSCALL "syscall"
static int push_event_header_attr(lua_State *L, const char *attr_name,
				  struct probe_event_header *eh)
{
	int err = CODE_FAILED;

	if (strncmp(attr_name, TGID_PID, sizeof(TGID_PID)) == 0) {
		lua_pushinteger(L, eh->tgid_pid);
		err = CODE_SUCCESS;
	} else if (strncmp(attr_name, EVENT_TIME, sizeof(EVENT_TIME)) == 0) {
		lua_pushinteger(L, eh->event_time);
		err = CODE_SUCCESS;
	} else if (strncmp(attr_name, COMM, sizeof(COMM)) == 0) {
		lua_pushstring(L, eh->comm);
		err = CODE_SUCCESS;
	} else if (strncmp(attr_name, SYSCALL, sizeof(SYSCALL)) == 0) {
		lua_pushinteger(L, eh->syscall_nr);
		err = CODE_SUCCESS;
	}

	return err;
}

static void push_exit_attr(lua_State *L, const char *attr_name, void *event_obj)
{
	int err;
	struct exit_event *e = (struct exit_event *)event_obj;

	ASSERT(IS_EXIT_EVENT(e->eh.syscall_nr),
	       "push_exit_attr: incorrect function called. event not exit");

	err = push_event_header_attr(L, attr_name, &e->eh);
	if (err != CODE_SUCCESS) {
		lua_pushnil(L);
	}
}

#define INODE "inode"
#define FAMILY "family"
#define TYPE "type"
static void push_socket_create_attr(lua_State *L, const char *attr_name,
				    void *event_obj)
{
	int err;
	char *family;
	char *type;
	struct socket_create *sinfo = (struct socket_create *)event_obj;

	ASSERT(sinfo->eh.syscall_nr == SYS_SOCKET,
	       "push_socket_create_attr: not socket create event");

	err = push_event_header_attr(L, attr_name, &sinfo->eh);
	if (err == CODE_SUCCESS)
		return;

	if (strncmp(attr_name, INODE, sizeof(INODE)) == 0) {
		lua_pushinteger(L, sinfo->i_ino);
	} else if (strncmp(attr_name, FAMILY, sizeof(FAMILY)) == 0) {
		family = socket_family_str(sinfo->family);
		if (family != NULL)
			lua_pushstring(L, family);
	} else if (strncmp(attr_name, TYPE, sizeof(TYPE)) == 0) {
		type = socket_type_str(sinfo->type);
		ASSERT(type != NULL, "push_socket_create_attr: type == NULL");
		lua_pushstring(L, type);
	} else {
		lua_pushnil(L);
	}
}

static void push_default(lua_State *L, const char *attr_name, void *event_obj)
{
	int err;
	struct probe_event_header *eh = (struct probe_event_header *)event_obj;

	err = push_event_header_attr(L, attr_name, eh);
	if (err != CODE_SUCCESS)
		lua_pushnil(L);
}

push_attr_fn get_push_attr_fn(int syscall)
{
	if (IS_EXIT_EVENT(syscall)) {
		return push_exit_attr;
	} else if (syscall == SYS_SOCKET) {
		return push_socket_create_attr;
	} else {
		return push_default;
	}

	return NULL;
}

