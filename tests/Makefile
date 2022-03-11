ROOT_DIR := ../

include $(ROOT_DIR)/Makefile.inc

UNIT := $(abspath ./unit)
TESTS := $(UNIT)

all: $(TESTS)

$(TESTS):
	$(MAKE) -C $@ all

clean:
	$(MAKE) -C $(UNIT) clean

.PHONY: all clean $(TESTS)


