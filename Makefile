# Get the path to the kernel build directory. This is the standard way to build
# external modules.
KDIR ?= /lib/modules/$(shell uname -r)/build

# Get the current directory of the module source code
PWD := $(shell pwd)

# The name of your module's compiled object file (will be demofs.o)
obj-m := demofs.o

# The list of object files to be linked into demofs.o.
# This specifies that demo_fs.o and inode.o (from the src/ directory) are
# part of the final module.
demofs-objs := src/demo_fs.o src/inode.o

# The 'all' target is the default one and is used to build the module.
# It invokes the kernel's build system to compile the module.
all:
	@echo "Building demofs module..."
	$(MAKE) -C $(KDIR) M=$(PWD) O=$(PWD)/builds modules

# The 'clean' target is used to remove all build artifacts.
# It uses the kernel's build system to clean up and also removes the local
# 'builds' directory.
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) O=$(PWD)/builds clean
	rm -rf builds
