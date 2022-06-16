ROOT_DIR := ..

include $(ROOT_DIR)/Makefile.inc

MAKE ?= make
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

# Kernel Headers
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

IDIRAFTER = --include-directory-after

SUBCLEAN = $(addsuffix .clean,$(SUPPORT))
BPFTOOL=$(TOOLS_DIR)/bpftool

SUPPORT = $(UTIL_DIR) $(ENGINE_DIR)
HASH = $(UTIL_DIR)/hash.o
SAFE = $(UTIL_DIR)/safe_hash.o
SYMSEARCH = $(UTIL_DIR)/symsearch.o
HELPERS_FN = $(UTIL_DIR)/helpers.o

RULE_ENGINE = $(DATABASE_DIR)/database.o \
			$(DATABASE_DIR)/rules.o \
			$(DATABASE_DIR)/notifier.o \
			$(ENGINE_DIR)/engine.o \
			$(ENGINE_DIR)/save_ms.o \
			$(LUA_DIR)/lua_engine.o \
			$(LUA_DIR)/lua_event.o \
			$(LUA_DIR)/lua_process.o \
			$(LUA_DIR)/attr_handler.o \
			$(LUA_DIR)/rule_manager.o \
			$(LUA_DIR)/lua_ms_tags.o \
			$(LUA_DIR)/lua_event_info.o \
			$(LUA_DIR)/lua_file_info.o \
			$(LUA_DIR)/lua_process_info.o \
			$(LUA_DIR)/lua_mmap_info.o \
			$(LUA_DIR)/lua_ptrace_info.o \
			$(LUA_DIR)/lua_socket_create_info.o \
			$(LUA_DIR)/lua_tcp_connection_info.o \
			$(LUA_DIR)/lua_module_load_info.o \
			$(LUA_DIR)/lua_modprobe_overwrite_info.o \
			$(LUA_DIR)/lua_process_lpe_info.o \
			$(LUA_DIR)/lua_helpers.o \

HELPERS = $(HASH) $(RULE_ENGINE) $(SYMSEARCH) $(HELPERS_FN) $(SAFE)
SQLITE3 = $(INC_DIR)/sqlite3.o
LUA_OBJ = $(INC_DIR)/liblua.a
THIRD_PARTY = $(SQLITE3) $(LIBBPF_OBJ) $(LUA_OBJ)

PRELIM_TARGETS = $(patsubst %.c,%.o, $(filter-out %.bpf.c, $(wildcard *.c)))
PROC_MONITOR = proc_monitor
LOADER = loader
MESSAGE = message
MESSAGE_LS = message_ls
APPS = $(PROC_MONITOR)
MESSAGE_CONSUMERS = consumer

PROC_MONITOR_LINK_FLAGS = -lelf -lz -ldl -lpthread -lm -lbsd

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - < /dev/null 2>&1 \
			 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

## TEMP FLAGS START. REMOVE LATER

ifeq ($(SINGULAR),y)
	SINGULAR_FLAG = -D__SINGULAR__
else
	SINGULAR_FLAG =
endif

## TEMP FLAGS END

.PHONY: all clean $(SUPPORT) $(SUBCLEAN)

all: $(PROC_MONITOR)

clean:	$(SUBCLEAN)
	$(call msg,CLEAN)
	$(Q)rm -f *.o
	$(Q)rm -f $(PROC_MONITOR).skel.h
	$(Q)rm -f $(PROC_MONITOR)
	$(Q)rm -f $(BUILD_DIR)/$(PROC_MONITOR)
	$(Q)rm vmlinux.h

$(SUBCLEAN): %.clean:
	$(Q)$(MAKE) -C $* clean

$(PROC_MONITOR).bpf.o: $(PROC_MONITOR).bpf.c $(LIBBPF_OBJ) $(wildcard %.h)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) 				\
		-D__BPF_HEADER__ 		\
		-DBPF_NO_PRESERVE_ACCESS_INDEX	\
		$(DEBUG_FLAG) 			\
		$(SINGULAR_FLAG) 		\
		-D__TARGET_ARCH_$(ARCH) 	\
		-D__KERNEL__ 			\
		-I$(INC_DIR) 			\
		-g3 -O2 -target bpf  		\
		$(CLANG_BPF_SYS_INCLUDES) 	\
		-c $(filter %.c,$^) 		\
		-o $@

# Generate bpf skeleton
$(PROC_MONITOR).skel.h: $(PROC_MONITOR).bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@


# Thread helpers
CONSUMER_HEADERS := $(wildcard %.h) $(UTIL_DIR)/util.h $(DATABASE_DIR)/database.h
$(MESSAGE_CONSUMERS).o: $(MESSAGE_CONSUMERS).c $(CONSUMER_HEADERS)
	$(call msg,CC,$@)
	$(Q)$(CC) -DAPPLY_ASSERT -DMULTI_THREADED $(CFLAGS) $(DEBUG_FLAG) $(INCLUDES) -c $(filter %.c, $^) -o $@

# Build helpers
$(SUPPORT):
	$(call msg,CC,$@)
	$(Q)$(MAKE) -C $@ all

# Build user-space code
$(MESSAGE).o: $(MESSAGE).c
	$(call msg,CC,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) $(DEBUG_FLAG) $(INCLUDES) -c $(filter %.c, $^) -o $@

# Build user-space code
$(MESSAGE_LS).o: $(MESSAGE_LS).c $(MESSAGE_LS).h
	$(call msg,CC,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) $(DEBUG_FLAG) $(INCLUDES) -c $(filter %.c, $^) -o $@


$(LOADER).o: $(LOADER).c $(PROC_MONITOR).skel.h
	$(call msg,CC,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) $(DEBUG_FLAG) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(PROC_MONITOR).o: $(PROC_MONITOR).c $(wildcard %.h) $(PROC_MONITOR).skel.h
	$(call msg,CC,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) $(DEBUG_FLAG) $(INCLUDES) -c $(filter %.c, $^) -o $@


# Build application binary
$(PROC_MONITOR): $(PRELIM_TARGETS) $(SUPPORT) $(THIRD_PARTY)
	$(call msg,CC,$@)
	$(Q)$(CC) -static $(CFLAGS) $(INCLUDES) $(DEBUG_FLAG) $(HELPERS) $(PRELIM_TARGETS) $(THIRD_PARTY) $(PROC_MONITOR_LINK_FLAGS) -o $@

.PHONY: all clean
