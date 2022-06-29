ROOT_DIR := ../../..

include $(ROOT_DIR)/Makefile.inc

ENGINE := lua_engine
EVENT := lua_event
PROCESS := lua_process
ATTR_HANDLER := attr_handler
PROCESS_ATTR_HANDLER := lua_process_attr_handler
MANAGER := rule_manager
HELPERS_FN := helpers_fn
TAGS := lua_ms_tags
EVENT_INFO := lua_event_info
FILE_INFO := lua_file_info
PROCESS_INFO := lua_process_info
MMAP_INFO := lua_mmap_info
PTRACE_INFO := lua_ptrace_info
SOCKET_CREATE_INFO := lua_socket_create_info
TCP_CONNECTION_INFO := lua_tcp_connection_info
MODULE_LOAD_INFO := lua_module_load_info
MODPROBE_OVERWRITE_INFO := lua_modprobe_overwrite_info
PROCESS_LPE_INFO := lua_process_lpe_info
HELPERS := lua_helpers

all: $(ENGINE).o \
	$(EVENT).o \
	$(PROCESS).o \
	$(ATTR_HANDLER).o \
	$(MANAGER).o \
	$(TAGS).o \
	$(EVENT_INFO).o \
	$(FILE_INFO).o \
	$(PROCESS_INFO).o \
	$(MMAP_INFO).o \
	$(PTRACE_INFO).o \
	$(SOCKET_CREATE_INFO).o \
	$(TCP_CONNECTION_INFO).o \
	$(MODULE_LOAD_INFO).o \
	$(MODPROBE_OVERWRITE_INFO).o \
	$(PROCESS_LPE_INFO).o \
	$(HELPERS).o \

$(ENGINE).o: $(ENGINE).c $(ENGINE).h
	$(call msg,LUA_ENGINE,$@)
	$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(ENGINE).c -o $@

$(EVENT).o: $(EVENT).c $(EVENT).h
	$(call msg,LUA_EVENT,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(EVENT).c -o $@

$(PROCESS).o: $(PROCESS).c $(PROCESS).h
	$(call msg,LUA_PROCESS,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(PROCESS).c -o $@

$(ATTR_HANDLER).o: $(ATTR_HANDLER).c $(ATTR_HANDLER).h
	$(call msg,ATTR_HANDLER,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(ATTR_HANDLER).c -o $@

$(MANAGER).o: $(MANAGER).c $(MANAGER).h
	$(call msg,RULE_MANAGER,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(MANAGER).c -o $@

$(TAGS).o: $(TAGS).c $(TAGS).h
	$(call msg,LUA_TAGS,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(TAGS).c -o $@

$(EVENT_INFO).o: $(EVENT_INFO).c $(EVENT_INFO).h
	$(call msg,LUA_EVENT_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(EVENT_INFO).c -o $@

$(FILE_INFO).o: $(FILE_INFO).c $(FILE_INFO).h
	$(call msg,LUA_FILE_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(FILE_INFO).c -o $@

$(PROCESS_INFO).o: $(PROCESS_INFO).c $(PROCESS_INFO).h
	$(call msg,LUA_PROCESS_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(PROCESS_INFO).c -o $@

$(MMAP_INFO).o: $(MMAP_INFO).c $(MMAP_INFO).h
	$(call msg,LUA_MMAP_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(MMAP_INFO).c -o $@

$(PTRACE_INFO).o: $(PTRACE_INFO).c $(PTRACE_INFO).h
	$(call msg,LUA_PTRACE_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(PTRACE_INFO).c -o $@

$(SOCKET_CREATE_INFO).o: $(SOCKET_CREATE_INFO).c $(SOCKET_CREATE_INFO).h
	$(call msg,LUA_SOCKET_CREATE_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(SOCKET_CREATE_INFO).c -o $@

$(TCP_CONNECTION_INFO).o: $(TCP_CONNECTION_INFO).c $(TCP_CONNECTION_INFO).h
	$(call msg,LUA_TCP_CONNECTION_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(TCP_CONNECTION_INFO).c -o $@

$(MODULE_LOAD_INFO).o: $(MODULE_LOAD_INFO).c $(MODULE_LOAD_INFO).h
	$(call msg,LUA_MODULE_LOAD_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(MODULE_LOAD_INFO).c -o $@

$(MODPROBE_OVERWRITE_INFO).o: $(MODPROBE_OVERWRITE_INFO).c $(MODPROBE_OVERWRITE_INFO).h
	$(call msg,LUA_MODPROBE_OVERWRITE_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(MODPROBE_OVERWRITE_INFO).c -o $@

$(PROCESS_LPE_INFO).o: $(PROCESS_LPE_INFO).c $(PROCESS_LPE_INFO).h
	$(call msg,LUA_PROCESS_LPE_INFO,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(PROCESS_LPE_INFO).c -o $@

$(HELPERS).o: $(HELPERS).c $(HELPERS).h
	$(call msg,LUA_HELPERS,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(HELPERS).c -o $@

clean:
	$(call msg,CLEAN)
	$(Q)rm -f *.o

.PHONY: all clean
