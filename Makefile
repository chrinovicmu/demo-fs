
MODULE_NAME := demofs

SRC_DIR := src
BUILD_DIR := builds

SRC_FILES := $(wildcard $(SRC_DIR)/*.c)

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-y := $(notdir $(SRC_FILES:.c=.o))

$(shell mkdir -p $(BUILD_DIR))

all:
	$(MAKE) -C $(KDIR) M=$(PWD)/$(BUILD_DIR) src=$(PWD)/$(SRC_DIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/$(BUILD_DIR) clean
	rm -rf $(BUILD_DIR)/*

install: all
	sudo insmod $(BUILD_DIR)/$(MODULE_NAME).ko

uninstall:
	sudo rmmod $(MODULE_NAME)

.PHONY: all clean install uninstall
