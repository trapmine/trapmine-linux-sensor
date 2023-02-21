ROOT_DIR := ../..

include $(ROOT_DIR)/Makefile.inc

DATABASE := database
ENGINE := engine
SAVE_MS := save_ms
LUA := lua
NOTIFIER := notifier
LISTENER := listener

all: $(DATABASE) $(ENGINE).o $(SAVE_MS).o $(LUA) $(NOTIFIER).o $(LISTENER).o

$(LUA):
	$(call msg,LUA,$@)
	$(Q)$(MAKE) -C $(LUA_DIR) all

$(DATABASE):
	$(call msg,DATABASE,$@)
	$(Q)$(MAKE) -C $(DATABASE_DIR) all

$(ENGINE).o: $(ENGINE).c $(ENGINE).h
	$(call msg,ENGINE,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(ENGINE).c -o $@

$(SAVE_MS).o: $(SAVE_MS).c $(SAVE_MS).h
	$(call msg,SAVE_MS,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(SAVE_MS).c -o $@

$(NOTIFIER).o: $(NOTIFIER).c $(NOTIFIER).h
	$(call msg,CC,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) $(INCLUDES) -c $(NOTIFIER).c -o $@

$(LISTENER).o: $(LISTENER).c $(LISTENER).h
	$(call msg,CC,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) $(INCLUDES) -c $(LISTENER).c -o $@

clean:
	$(call msg,CLEAN)
	$(Q)$(MAKE) -C $(DATABASE_DIR) clean
	$(Q)$(MAKE) -C $(LUA_DIR) clean
	$(Q)rm -f *.o

.PHONY: all clean $(DATABASE) $(LUA)
