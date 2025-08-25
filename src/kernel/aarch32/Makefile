# Makefile for hello character device driver
# For Linux 4.4.27 kernel with armv7-eabihf toolchain

# Object file to build
obj-m += hello.o

# Kernel source directory
KERNEL_SRC := ../../../toolchain/kernel/linux-4.4.27

# Cross compiler toolchain
CROSS_COMPILE := ../../../toolchain/armv7-eabihf--glibc--stable-2018.11-1/bin/arm-buildroot-linux-gnueabihf-

# Architecture
ARCH := arm

# Default target
all:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_SRC) M=$(PWD) modules

# Clean except hello.ko
clean:
	rm -rf *.cmd *.mod.* *.symvers *.order *.o .tmp_versions .hello.*

# Clean target
distclean:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_SRC) M=$(PWD) clean

# Help target
help:
	@echo "Available targets:"
	@echo "  all         - Build the kernel module"
	@echo "  clean 		 - clean except hello.ko"
	@echo "  distclean   - Clean build artifacts"
	@echo "  help        - Show this help message"

.PHONY: all distclean install help
