ROOT_DIR := ../../..

include $(ROOT_DIR)/Makefile.inc

ENGINE := lua_engine
EVENT := lua_event
ATTR_HANDLER := attr_handler
MANAGER := rule_manager
HELPERS_FN := helpers_fn

all: $(ENGINE).o $(EVENT).o $(ATTR_HANDLER).o $(MANAGER).o $(HELPERS_FN).o

$(ENGINE).o: $(ENGINE).c $(ENGINE).h
	$(call msg,LUA_ENGINE,$@)
	$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(ENGINE).c -o $@

$(EVENT).o: $(EVENT).c $(EVENT).h
	$(call msg,LUA_EVENT,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(EVENT).c -o $@

$(ATTR_HANDLER).o: $(ATTR_HANDLER).c $(ATTR_HANDLER).h
	$(call msg,ATTR_HANDLER,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(ATTR_HANDLER).c -o $@

$(MANAGER).o: $(MANAGER).c $(MANAGER).h
	$(call msg,RULE_MANAGER,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(MANAGER).c -o $@

$(HELPERS_FN).o: $(HELPERS_FN).c $(HELPERS_FN).h
	$(call msg,LUA_HELPERS,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(HELPERS_FN).c -o $@

clean:
	$(call msg,CLEAN)
	$(Q)rm -f *.o

.PHONY: all clean
