ROOT_DIR := ../..

include $(ROOT_DIR)/Makefile.inc

DATABASE := database
CONTEXT := context
ENGINE := engine

all: $(DATABASE) $(CONTEXT) $(ENGINE).o

$(DATABASE):
	$(call msg,DATABASE,$@)
	$(Q)$(MAKE) -C $(DATABASE_DIR) all

$(CONTEXT):
	$(call msg,CONTEXT,$@)
	$(Q)$(MAKE) -C $(CONTEXT_DIR) all

$(ENGINE).o: $(ENGINE).c $(ENGINE).h
	$(call msg,ENGINE,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(ENGINE).c -o $@

clean:
	$(call, msg,CLEAN)
	$(Q)$(MAKE) -C $(DATABASE_DIR) clean
	$(Q)$(MAKE) -C $(CONTEXT_DIR) clean
	$(Q)rm -f *.o

.PHONY: all clean $(DATABASE) $(CONTEXT)
