ROOT_DIR := ../../..

include $(ROOT_DIR)/Makefile.inc

DATABASE := database
RULES := rules
HEADER_DEPENDENCIES := stmts.h schema.h helper_defs.h

all: $(DATABASE).o $(RULES).o

INC := $(INCLUDES)

$(RULES).o: $(RULES).c $(RULES).h
	$(call msg,CC,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) $(INC) -c $(RULES).c -o $@

$(DATABASE).o: $(DATABASE).c $(DATABASE).h $(HEADER_DEPENDENCIES)
	$(call msg,CC,$@)
	$(Q)$(CC) -DAPPLY_ASSERT $(CFLAGS) $(INCLUDES) -c $(DATABASE).c -o $@

.PHONY: clean

clean:
	$(Q)rm -f *.o

