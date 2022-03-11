ROOT_DIR := ..

include $(ROOT_DIR)/Makefile.inc

LIBBPF_SRC := $(abspath ./libbpf/src)

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
endif

SQLITE := sqlite

LIBS := $(LIBBPF_OBJ) $(SQLITE)

all: $(LIBS)

clean:
	$(call msg,CLEAN)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) clean
	$(Q)rm -rf *.o

OBJECTS=$(patsubst %.c,%.o,$(wildcard *.c))

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
	$(call msg,CP,$@)
	$(Q)$(MAKE) -C $(SQLITE3_DIR) all

