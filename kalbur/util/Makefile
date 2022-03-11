ROOT_DIR := ../..

include $(ROOT_DIR)/Makefile.inc

HASH = hash
UTIL = util
SYMSEARCH = symsearch

all: $(HASH).o $(SYMSEARCH).o

$(HASH).o: $(HASH).h $(HASH).c $(UTIL).h
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(HASH).c -o $@


$(SYMSEARCH).o: $(SYMSEARCH).h $(SYMSEARCH).c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(SYMSEARCH).c -o $@

.PHONY: clean

clean:
	$(Q)rm -f *.o


