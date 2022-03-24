ROOT_DIR := ../../..

include $(ROOT_DIR)/Makefile.inc

MANAGER := context_manager
POPULATE := populate

all: $(MANAGER).o $(POPULATE).o

$(MANAGER).o: $(MANAGER).h $(MANAGER).c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(MANAGER).c -o $@

$(POPULATE).o: $(POPULATE).h $(POPULATE).c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(POPULATE).c -o $@

clean:
	$(Q)rm -f *.o

.PHONY: all clean
