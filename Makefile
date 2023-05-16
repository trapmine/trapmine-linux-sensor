ROOT_DIR := .

include $(ROOT_DIR)/Makefile.inc

SENSOR_CORE := sensor-core
VMLINUX_H := "vmlinux_5.15.0-60-generic.h"

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf ' %-8s %s%s\n'					\
	      		"$(1)"						\
			"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
			"$(if $(3), $(3))"; 
endif

LIB := 3rd_party
TESTS := $(abspath ./tests)

TARGETS := $(KALBUR) $(LIB)

all: $(TARGETS)

install: 
	$(call msg,INSTALL,$@)
	@./scripts/install.sh

build-test: $(TARGETS) $(TESTS)

$(KALBUR): | $(LIB)
	$(call msg,KALBUR,$@)
	$(Q)rm $(KALBUR_DIR)/vmlinux.h || echo "vmlinux.h not present"
	$(Q)ln -s $(KALBUR_DIR)/$(VMLINUX_H) $(KALBUR_DIR)/vmlinux.h
	$(Q)$(MAKE) -C $(KALBUR_DIR) all
	$(Q)mv $(KALBUR_DIR)/proc_monitor $(BUILD_DIR)/$(SENSOR_CORE)

$(TESTS):
	$(call msg,TESTS,$@)
	$(Q)$(MAKE) -C $@ all

$(LIB):
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIB_DIR) all

clean:
	$(Q)$(MAKE) -C $(KALBUR_DIR) clean
	$(Q)$(MAKE) -C $(LIB_DIR) clean
	$(Q)$(MAKE) -C $(TESTS) clean
	@ find $(ROOT_DIR)/include ! -name '.gitignore' -type f -exec rm -f {} +
	@ find $(ROOT_DIR)/include ! -name 'include' -type d -exec rm -rf {} +

.PHONY: $(TARGETS) $(TESTS) all build-tests install clean

APP_NAME := linux-sensor
IMAGE_BASE := $(APP_NAME)/core:latest

demo-build:
	docker build -t $(IMAGE_BASE) --label "type=$(APP_NAME)" .

demo-run:
	docker run --rm -it $(IMAGE_BASE) bash
