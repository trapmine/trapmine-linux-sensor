ROOT_DIR := ../..

include $(ROOT_DIR)/Makefile.inc

DATABASE := database
CONTEXT := context

all: $(DATABASE) $(CONTEXT)

$(DATABASE):
	$(call msg,DATABASE,$@)
	$(Q)$(MAKE) -C $(DATABASE_DIR) all

$(CONTEXT):
	$(call msg,CONTEXT,$@)
	$(Q)$(MAKE) -C $(CONTEXT_DIR) all

clean:
	$(call, msg,CLEAN)
	$(Q)$(MAKE) -C $(DATABASE_DIR) clean

.PHONY: $(DATABASE) $(CONTEXT)
