# Get the path to the kernel build directory.
KDIR ?= /lib/modules/$(shell uname -r)/build

# Get the current directory of the module source code
PWD := $(shell pwd)

# The name of your module's compiled object file
obj-m := demofs.o

# The list of object files
demofs-objs := src/demo_fs.o src/inode.o

# The 'all' target to build the module.
all:
	@echo "Building demofs module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# The 'clean' target to remove all build artifacts.
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
