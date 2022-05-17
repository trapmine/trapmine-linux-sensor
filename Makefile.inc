ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf ' %-8s %s%s\n'					\
	      		"$(1)"						\
			"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
			"$(if $(3), $(3))"; 
endif

ifeq ($(DEBUG),bpf)
	DEBUG_FLAG = -D__DEBUG_BPF__
else ifeq ($(DEBUG),user)
	DEBUG_FLAG = -D__DEBUG__
else ifeq ($(DEBUG),all)
	DEBUG_FLAG = -D__DEBUG__ -D__DEBUG_BPF__
else
	DEBUG_FLAG =
endif


KALBUR := kalbur
RULE_ENGINE_DIR := rule_engine
UTIL := util
LUA_ENGINE := lua
DATABASE := database

# Paths
INC_DIR = $(abspath $(ROOT_DIR)/include)
LIB_DIR = $(abspath $(ROOT_DIR)/third_party)
BUILD_DIR = $(abspath $(ROOT_DIR)/build)
TOOLS_DIR = $(abspath $(ROOT_DIR)/tools)
KALBUR_DIR = $(abspath $(ROOT_DIR)/$(KALBUR))
ENGINE_DIR = $(KALBUR_DIR)/$(RULE_ENGINE_DIR)
DATABASE_DIR = $(ENGINE_DIR)/$(DATABASE)
UTIL_DIR = $(KALBUR_DIR)/$(UTIL)
LUA_DIR = $(ENGINE_DIR)/$(LUA_ENGINE)
LUA_LIB_DIR = $(LIB_DIR)/lua

# Libraries
LIBBPF_OBJ := $(INC_DIR)/libbpf.a
SQLITE3_DIR := $(LIB_DIR)/sqlite3

# Kernel headers
UAPI := $(LIB_DIR)/libbpf/include/uapi

# Commands
CC ?= gcc
MAKE ?= make

IMPL_CFLAGS :=	-Wmissing-prototypes \
		-Wno-unused-parameter \
		-fno-omit-frame-pointer \
		-g -rdynamic	# <- DEBUG OPTIONS

AIRBUS_SEC_FLAGS := 	-O2 							\
			-Wall -Wextra -Wpedantic -Wformat=2 		\
			-Wformat-overflow=2 -Wformat-truncation=2 		\
			-Wformat-security -Wnull-dereference -Wstack-protector 	\
			-Wtrampolines -Walloca -Wvla -Warray-bounds=2 		\
			-Wimplicit-fallthrough=3 -Wtraditional-conversion 	\
			-Wshift-overflow=2 -Wcast-qual -Wstringop-overflow=4 	\
			-Wconversion -Warith-conversion -Wlogical-op 		\
			-Wduplicated-cond -Wduplicated-branches 		\
			-Wformat-signedness -Wshadow -Wstrict-overflow=4 	\
			-Wundef -Wstrict-prototypes -Wswitch-default 		\
			-Wswitch-enum -Wstack-usage=1000000 -Wcast-align=strict \
			-D_FORTIFY_SOURCE=2 -fstack-protector-strong 		\
			-fstack-clash-protection -fPIE -Wl,-z,relro -Wl,-z,now 	\
			-Wl,-z,noexecstack -Wl,-z,separate-code


INCLUDES := -I$(INC_DIR) -I$(ROOT_DIR) -I$(KALBUR_DIR) -I$(DATABASE_DIR) -I$(UTIL_DIR) -I$(UAPI) -I$(ENGINE_DIR) -I$(LUA_DIR)
CFLAGS ?= $(IMPL_CFLAGS) $(AIRBUS_SEC_FLAGS)
