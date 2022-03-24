ROOT_DIR := ../..

include $(ROOT_DIR)/Makefile.inc

HASH = hash
UTIL = util
SYMSEARCH = symsearch
HELPERS := helpers
SAFE := safe_hash

all: $(HASH).o $(SYMSEARCH).o $(HELPERS).o $(SAFE).o

$(HASH).o: $(HASH).h $(HASH).c $(UTIL).h
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(HASH).c -o $@


$(SYMSEARCH).o: $(SYMSEARCH).h $(SYMSEARCH).c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(SYMSEARCH).c -o $@

$(HELPERS).o: $(HELPERS).c $(HELPERS).h
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(HELPERS).c -o $@

$(SAFE).o: $(SAFE).c $(SAFE).h $(UTIL).h $(HASH).h
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(SAFE).c -o $@

.PHONY: clean

clean:
	$(Q)rm -f *.o


