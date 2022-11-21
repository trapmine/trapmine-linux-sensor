ROOT_DIR := ..

include $(ROOT_DIR)/Makefile.inc

LIBBPF_SRC := $(abspath ./libbpf/src)

SQLITE := sqlite3
LUA := $(INC_DIR)/lua.o

LIBS := $(LIBBPF_OBJ) $(SQLITE) $(LUA)

all: $(LIBS)

clean:
	$(call msg,CLEAN)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) clean
	$(Q)$(MAKE) -C $(LUA_LIB_DIR) clean
	$(Q)rm -rf *.o


$(INC_DIR)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(INC_DIR)/libbpf
	$(call msg,LIBBPF,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

$(SQLITE):
	$(call msg,SQLITE,$@)
	$(Q)$(MAKE) -C $(SQLITE3_DIR) all

$(LUA):
	$(call msg,LUA,$@)
	$(MAKE) -C $(LUA_LIB_DIR)
	$(Q)cp lua/lua.h $(INC_DIR)/lua.h
	$(Q)cp lua/luaconf.h $(INC_DIR)/luaconf.h
	$(Q)cp lua/lauxlib.h $(INC_DIR)/lauxlib.h
	$(Q)cp lua/lualib.h $(INC_DIR)/lualib.h
	$(Q)cp lua/liblua.a $(INC_DIR)/liblua.a

.PHONY: all clean $(SQLITE) $(LUA)
