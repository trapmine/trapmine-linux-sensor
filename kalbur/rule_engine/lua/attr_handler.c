#include <syscall_defs.h>
#include <lua.h>
#include <err.h>
#include <string.h>
#include <sys/socket.h> // AF_INET, AF_INET6
#include <arpa/inet.h>
#include <helpers.h>
#include <events.h>
#include <stdlib.h>
#include <stdio.h>
#include "attr_handler.h"

#define ATTRIBUTE_HANDLER(fn)                                                  \
	static void fn(lua_State *L, const char *attr_name,                    \
		       struct message_state *event_obj)

#define IS_ATTR(attr_name, attr) strncmp(attr_name, attr, sizeof(attr)) == 0

#define TGID_PID "pid"
#define EVENT_TIME "eventTime"
#define COMM "processName"
#define SYSCALL "syscall"
static int push_event_header_attr(lua_State *L, const char *attr_name,
				  struct probe_event_header *eh)
{
	if (IS_ATTR(attr_name, TGID_PID)) {
		lua_pushinteger(L, (long)(eh->tgid_pid >> 32));
		return CODE_SUCCESS;
	} else if (IS_ATTR(attr_name, EVENT_TIME)) {
		lua_pushinteger(L, (long)eh->event_time);
		return CODE_SUCCESS;
	} else if (IS_ATTR(attr_name, COMM)) {
		lua_pushstring(L, eh->comm);
		return CODE_SUCCESS;
	} else if (IS_ATTR(attr_name, SYSCALL)) {
		lua_pushinteger(L, (long)eh->syscall_nr);
		return CODE_SUCCESS;
	}

	return CODE_FAILED;
}

#define PPID "ppid"
#define CLONE_FLAGS "cloneFlags"
#define FILENAME "filename"
#define CMDLINE "cmdline"
#define ENV "env"
#define INTERP "interpreter"
#define STDIN "stdin"
#define STDOUT "stdout"
#define STDERR "stderr"
ATTRIBUTE_HANDLER(push_proc_launch_attr)
{
	int err;
	char *filename, *cmdline, *env, *interp;
	char std[64];
	struct stdio io;
	struct process_info *pinfo =
		(struct process_info *)event_obj->primary_data;
	char *string_data = MESSAGE_STRING(event_obj);

	ASSERT(IS_PROCESS_LAUNCH(pinfo->eh.syscall_nr),
	       "push_proc_launch_attr: not process launch event");

	err = push_event_header_attr(L, attr_name, &pinfo->eh);
	if (err == CODE_SUCCESS)
		return;

	if (IS_ATTR(attr_name, PPID)) {
		lua_pushinteger(L, (long)pinfo->ppid >> 32);
	} else if (IS_ATTR(attr_name, CLONE_FLAGS)) {
		lua_pushinteger(L, (long)pinfo->clone_flags);
	} else if (IS_ATTR(attr_name, FILENAME)) {
		if (string_data == NULL)
			return;

		filename = build_filename_from_event(
			&string_data[pinfo->file.file_offset],
			pinfo->file.path_len);
		if (filename != NULL) {
			lua_pushstring(L, filename);
			free(filename);
		} else {
			lua_pushnil(L);
		}
	} else if (IS_ATTR(attr_name, CMDLINE)) {
		if (string_data == NULL)
			return;

		cmdline = build_cmdline(string_data, pinfo->args.argv_offset,
					(unsigned long)pinfo->args.nbytes);
		if (cmdline != NULL) {
			lua_pushstring(L, cmdline);
			free(cmdline);
		} else {
			lua_pushnil(L);
		}
	} else if (IS_ATTR(attr_name, ENV)) {
		if (string_data == NULL)
			return;

		env = build_env(string_data, pinfo->env.env_offset,
				(unsigned long)pinfo->env.nbytes);
		if (env != NULL) {
			lua_pushstring(L, env);
			free(env);
		} else {
			lua_pushnil(L);
		}
	} else if (IS_ATTR(attr_name, INTERP)) {
		interp = get_interpreter_string(string_data, pinfo->interp_str_offset);
		if (interp != NULL) {
			lua_pushstring(L, interp);
		}
		else {
			lua_pushnil(L);
		}
	} else if (IS_ATTR(attr_name, STDIN)) {
		io = pinfo->io[STDIN_INDX];
		if (io.type == STD_SOCK) {
			sprintf(std, "socket-%lu", io.std_ino);
			lua_pushstring(L, std);
		} else {
			lua_pushnil(L);
		}
	} else if (IS_ATTR(attr_name, STDOUT)) {
		io = pinfo->io[STDOUT_INDX];
		if (io.type == STD_SOCK) {
			sprintf(std, "socket-%lu", io.std_ino);
			printf("Inside attr handler: %s\n", std);
			lua_pushstring(L, std);
		} else {
			lua_pushnil(L);
		}
	} else if (IS_ATTR(attr_name, STDERR)) {
		io = pinfo->io[STDERR_INDX];
		if (io.type == STD_SOCK) {
			sprintf(std, "socket-%lu", io.std_ino);
			lua_pushstring(L, std);
		} else {
			lua_pushnil(L);
		}
	} else {
		lua_pushnil(L);
	}
}

ATTRIBUTE_HANDLER(push_exit_attr)
{
	int err;
	struct exit_event *e = (struct exit_event *)event_obj->primary_data;

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
ATTRIBUTE_HANDLER(push_socket_create_attr)
{
	int err;
	char *family;
	char *type;
	struct socket_create *sinfo =
		(struct socket_create *)event_obj->primary_data;

	ASSERT(sinfo->eh.syscall_nr == SYS_SOCKET,
	       "push_socket_create_attr: not socket create event");

	err = push_event_header_attr(L, attr_name, &sinfo->eh);
	if (err == CODE_SUCCESS)
		return;

	if (IS_ATTR(attr_name, INODE)) {
		lua_pushinteger(L, (long)sinfo->i_ino);
	} else if (IS_ATTR(attr_name, FAMILY)) {
		family = socket_family_str(sinfo->family);
		if (family != NULL)
			lua_pushstring(L, family);
		else
			lua_pushnil(L);
	} else if (IS_ATTR(attr_name, TYPE)) {
		type = socket_type_str(sinfo->type);
		ASSERT(type != NULL, "push_socket_create_attr: type == NULL");
		lua_pushstring(L, type);
	} else {
		lua_pushnil(L);
	}
}

#define SPORT "sport"
#define DPORT "dport"
#define SADDR "saddr"
#define DADDR "daddr"
#define DIRECTION "direction"
ATTRIBUTE_HANDLER(push_tcp_attr)
{
	int err, syscall;
	char *type;
	void *saddrn;
	void *daddrn;
	char saddrp[50] = { 0 };
	char daddrp[50] = { 0 };
	char direction[16] = { 0 };

	tcp_info_t *t = (tcp_info_t *)event_obj->primary_data;

	syscall = t->t4.eh.syscall_nr;
	ASSERT((syscall == SYS_ACCEPT) || (syscall == SYS_CONNECT),
	       "push_tcp_attr: not tcp event");

	err = push_event_header_attr(L, attr_name, &t->t4.eh);
	if (err == CODE_SUCCESS)
		return;

	if (syscall == SYS_CONNECT)
		memcpy(direction, "outgoing\0", 10UL);
	else
		memcpy(direction, "incoming\0", 10UL);

	if (t->t4.type == AF_INET) {
		saddrn = &t->t4.saddr;
		daddrn = &t->t4.daddr;
	} else if (t->t4.type == AF_INET6) {
		saddrn = t->t6.saddr;
		daddrn = t->t6.daddr;
	} else {
		saddrn = NULL;
		daddrn = NULL;
	}

	if (IS_ATTR(attr_name, INODE)) {
		lua_pushinteger(L, (long)t->t4.i_ino);
	} else if (IS_ATTR(attr_name, TYPE)) {
		type = socket_family_str((int)t->t4.type);
		if (type != NULL)
			lua_pushstring(L, type);
		else
			lua_pushnil(L);
	} else if (IS_ATTR(attr_name, SPORT)) {
		lua_pushinteger(L, (long)t->t4.sport);
	} else if (IS_ATTR(attr_name, DPORT)) {
		lua_pushinteger(L, (long)t->t4.dport);
	} else if (IS_ATTR(attr_name, DADDR)) {
		if (daddrn != NULL) {
			inet_ntop((int)t->t4.type, daddrn, daddrp, 50);
			lua_pushstring(L, daddrp);
		} else
			lua_pushnil(L);
	} else if (IS_ATTR(attr_name, SADDR)) {
		if (saddrn != NULL) {
			inet_ntop((int)t->t4.type, saddrn, saddrp, 50);
			lua_pushstring(L, saddrp);
		} else
			lua_pushnil(L);
	} else if (IS_ATTR(attr_name, DIRECTION)) {
		lua_pushstring(L, direction);
	} else {
		lua_pushnil(L);
	}
}

#define REQUEST "request"
#define ADDR "address"
#define TARGET_PID "targetPid"
ATTRIBUTE_HANDLER(push_ptrace_attr)
{
	int err;
	struct ptrace_event_info *ptrace =
		(struct ptrace_event_info *)event_obj->primary_data;

	ASSERT(ptrace->eh.syscall_nr == SYS_PTRACE,
	       "push_ptrace_attr: not ptrace event");

	err = push_event_header_attr(L, attr_name, &ptrace->eh);
	if (err == CODE_SUCCESS)
		return;

	if (IS_ATTR(attr_name, REQUEST)) {
		lua_pushinteger(L, ptrace->request);
	} else if (IS_ATTR(attr_name, ADDR)) {
		lua_pushinteger(L, (long)ptrace->addr);
	} else if (IS_ATTR(attr_name, TARGET_PID)) {
		lua_pushinteger(L, (long)ptrace->target_tgid_pid >> 32);
	} else {
		lua_pushnil(L);
	}
}

ATTRIBUTE_HANDLER(push_kmodule_attr)
{
	int err;
	char *filename;

	struct kernel_module_load_info *kmod_info =
		(struct kernel_module_load_info *)event_obj->primary_data;
	char *string_data = MESSAGE_STRING(event_obj);

	ASSERT(kmod_info->eh.syscall_nr == SYS_FINIT_MODULE,
	       "push_kmodule_attr: not a kernel module load event");

	err = push_event_header_attr(L, attr_name, &kmod_info->eh);
	if (err == CODE_SUCCESS)
		return;

	if (IS_ATTR(attr_name, FILENAME)) {
		if (string_data == NULL)
			return;

		filename = build_filename_from_event(
			&string_data[kmod_info->f.file_offset],
			kmod_info->f.path_len);
		if (filename != NULL) {
			lua_pushstring(L, filename);
			free(filename);
		} else {
			lua_pushnil(L);
		}
	} else {
		lua_pushnil(L);
	}
}

static void push_default(lua_State *L, const char *attr_name,
			 struct message_state *event_obj)
{
	int err;
	struct probe_event_header *eh =
		(struct probe_event_header *)event_obj->primary_data;

	err = push_event_header_attr(L, attr_name, eh);
	if (err != CODE_SUCCESS)
		lua_pushnil(L);
}

push_attr_fn get_push_attr_fn(int syscall)
{
	if (IS_EXIT_EVENT(syscall)) {
		return push_exit_attr;
	} else if (IS_PROCESS_LAUNCH(syscall)) {
		return push_proc_launch_attr;
	} else if (syscall == SYS_SOCKET) {
		return push_socket_create_attr;
	} else if (syscall == SYS_ACCEPT) {
		return push_tcp_attr;
	} else if (syscall == SYS_CONNECT) {
		return push_tcp_attr;
	} else if (syscall == SYS_FINIT_MODULE) {
		return push_kmodule_attr;
	} else if (syscall == SYS_PTRACE) {
		return push_ptrace_attr;
	} else {
		return push_default;
	}

	return NULL;
}

