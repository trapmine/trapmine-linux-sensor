ROOT_DIR := ../../..

include $(ROOT_DIR)/Makefile.inc

ENGINE := lua_engine

all: $(ENGINE).o

$(ENGINE).o: $(ENGINE).c $(ENGINE).h
	$(call msg,LUA_ENGINE,$@)
	$(CC) -DAPPLY_ASSERT $(DEBUG_FLAG) $(CFLAGS) $(INCLUDES) -c $(ENGINE).c -o $@

clean:
	$(call msg,CLEAN)
	$(Q)rm -f *.o

.PHONY: all clean
