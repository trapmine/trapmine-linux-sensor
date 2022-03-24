ROOT_DIR := ../..

include $(ROOT_DIR)/Makefile.inc

DATABASE := database

all: $(DATABASE)

$(DATABASE):
	$(call msg,DATABASE,$@)
	$(Q)$(MAKE) -C $(DATABASE_DIR) all

clean:
	$(call, msg,CLEAN)
	$(Q)$(MAKE) -C $(DATABASE_DIR) clean

.PHONY: $(DATABASE)
