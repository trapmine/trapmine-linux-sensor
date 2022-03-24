ROOT_DIR := ../../..

include $(ROOT_DIR)/Makefile.inc

CONTEXT := context

$(CONTEXT).o: $(CONTEXT).h $(CONTEXT).c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(CONTEXT).c -o $@


clean:
	$(Q)rm -f *.o
