# Source for sqlite amalgamation: https://www.sqlite.org/download.html

ROOT_DIR := ../..

include $(ROOT_DIR)/Makefile.inc

SQLITE3 = sqlite3
SQLITE3_LINKS = -lpthread -lm -ldl
SQLITE3_CFLAGS := -DSQLITE_OMIT_LOAD_EXTENSION \
		 -DSQLITE_THREADSAFE=2 \
		 -DSQLITE_DEFAULT_FOREIGN_KEYS=1 \
		 -DSQLITE_DQS=0 \
                 -DSQLITE_CORE

SQLITE3_CFLAGS_DEBUG := -DSQLITE_DEBUG \
			-DSQLITE_ENABLE_EXPLAIN_COMMENTS \
			-DSQLITE_ENABLE_SELECTTRACE \
			-DSQLITE_ENABLE_WHERETRACE 


OUTPUT := $(INC_DIR)/sqlite3.o

HEADER := $(SQLITE3_DIR)/sqlite3.h

all: $(OUTPUT) install

install: 
	$(Q)$(call msg,CP,$(HEADER))
	$(Q)cp -n $(HEADER) $(INC_DIR)

$(OUTPUT):
	$(Q)$(call msg,GCC,$(OUTPUT))
	$(Q)gcc -c -static $(SQLITE3_DIR)/sqlite3.c $(SQLITE_CFLAGS) -o $@

.PHONY: all

