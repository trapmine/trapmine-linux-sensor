ROOT_DIR := ../..

include $(ROOT_DIR)/Makefile.inc

HASH := $(UTIL_DIR)/hash.o $(UTIL_DIR)/hash.h $(UTIL_DIR)/util.h
SQLITE3 := $(INC_DIR)/sqlite3.o
DB := $(DATABASE_DIR)/database.o
NOTIFIER := $(DATABASE_DIR)/notifier.o
RULES := $(DATABASE_DIR)/rules.o
CHECK_FLAGS := -pthread -I/usr/local/include -L/usr/local/lib -lcheck
DEPENDENCIES := $(HASH) $(DB) $(SQLITE3) $(NOTIFIER) $(RULES)

TESTS := check_message check_database
all: $(TESTS)

TRACK := $(wildcard $(UTIL_DIR)/*.c) $(wildcard $(DATABASE_DIR)/*.c) $(wildcard $(KALBUR_DIR)/*.c)
$(TESTS): $(TESTS).c $(TRACK)
	$(Q)$(CC) $(CHECK_FLAGS) $(DEPENDENCIES) $(INCLUDES) $@.c -o $@ -ldl

clean:
	rm -f $(TESTS)

.PHONY: all clean
