ROOT_DIR := ../..

include $(ROOT_DIR)/Makefile.inc

DATABASE := database
CONTEXT := context
ENGINE := engine
SAVE_MS := save_ms

all: $(DATABASE) $(CONTEXT) $(ENGINE).o $(SAVE_MS).o

$(DATABASE):
	$(call msg,DATABASE,$@)
	$(Q)$(MAKE) -C $(DATABASE_DIR) all

$(CONTEXT):
	$(call msg,CONTEXT,$@)
	$(Q)$(MAKE) -C $(CONTEXT_DIR) all

$(ENGINE).o: $(ENGINE).c $(ENGINE).h
	$(call msg,ENGINE,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) $(INCLUDES) -c $(ENGINE).c -o $@

$(SAVE_MS).o: $(SAVE_MS).c $(SAVE_MS).h
	$(call msg,SAVE_MS,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) -DAPPLY_ASSERT $(INCLUDES) -c $(SAVE_MS).c -o $@

clean:
	$(call, msg,CLEAN)
	$(Q)$(MAKE) -C $(DATABASE_DIR) clean
	$(Q)$(MAKE) -C $(CONTEXT_DIR) clean
	$(Q)rm -f *.o

.PHONY: all clean $(DATABASE) $(CONTEXT)
