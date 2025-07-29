# Multi-Architecture Cross-Compilation Makefile
# Author: Jelasin
# Date: July 29, 2025

# Source file
SRC_FILE = src/stack/hello.c

# Toolchain directory
TOOLCHAIN_DIR = toolchain

# Architecture definitions
AARCH64_TOOLCHAIN = $(TOOLCHAIN_DIR)/aarch64--glibc--stable-2024.05-1/bin/aarch64-linux-gcc
AARCH32_TOOLCHAIN = $(TOOLCHAIN_DIR)/armv7-eabihf--glibc--stable-2024.05-1/bin/arm-linux-gcc
MIPS_TOOLCHAIN = $(TOOLCHAIN_DIR)/mips32--glibc--stable-2024.05-1/bin/mips-linux-gcc
MIPSEL_TOOLCHAIN = $(TOOLCHAIN_DIR)/mips32el--glibc--stable-2024.05-1/bin/mipsel-linux-gcc
PPC_TOOLCHAIN = $(TOOLCHAIN_DIR)/powerpc-440fp--glibc--stable-2024.05-1/bin/powerpc-linux-gcc
RISCV32_TOOLCHAIN = $(TOOLCHAIN_DIR)/riscv32-ilp32d--glibc--stable-2024.05-1/bin/riscv32-linux-gcc
RISCV64_TOOLCHAIN = $(TOOLCHAIN_DIR)/riscv64-lp64d--glibc--stable-2024.05-1/bin/riscv64-linux-gcc

# Compiler flags
CFLAGS = -no-pie -fno-stack-protector -O0 -g
LDFLAGS_STATIC = -static
LDFLAGS_DYNAMIC = 

# Output directories
AARCH64_DIR = aarch64/stack
AARCH32_DIR = aarch32/stack
MIPS_DIR = mips/stack
MIPSEL_DIR = mipsel/stack
PPC_DIR = ppc/stack
RISCV32_DIR = riscv32/stack
RISCV64_DIR = riscv64/stack

# Default target
.PHONY: all stack-hello clean help

all: stack-hello

stack-hello: stack-hello-aarch64 stack-hello-aarch32 stack-hello-mips stack-hello-mipsel stack-hello-ppc stack-hello-riscv32 stack-hello-riscv64

# AArch64 targets
stack-hello-aarch64: $(AARCH64_DIR)/hello_dyn $(AARCH64_DIR)/hello_static

$(AARCH64_DIR)/hello_dyn: $(SRC_FILE)
	@echo "Building AArch64 dynamic binary..."
	$(AARCH64_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_DYNAMIC) -o $@ $<

$(AARCH64_DIR)/hello_static: $(SRC_FILE)
	@echo "Building AArch64 static binary..."
	$(AARCH64_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_STATIC) -o $@ $<

# AArch32 targets
stack-hello-aarch32: $(AARCH32_DIR)/hello_dyn $(AARCH32_DIR)/hello_static

$(AARCH32_DIR)/hello_dyn: $(SRC_FILE)
	@echo "Building AArch32 dynamic binary..."
	$(AARCH32_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_DYNAMIC) -o $@ $<

$(AARCH32_DIR)/hello_static: $(SRC_FILE)
	@echo "Building AArch32 static binary..."
	$(AARCH32_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_STATIC) -o $@ $<

# MIPS targets
stack-hello-mips: $(MIPS_DIR)/hello_dyn $(MIPS_DIR)/hello_static

$(MIPS_DIR)/hello_dyn: $(SRC_FILE)
	@echo "Building MIPS dynamic binary..."
	$(MIPS_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_DYNAMIC) -o $@ $<

$(MIPS_DIR)/hello_static: $(SRC_FILE)
	@echo "Building MIPS static binary..."
	$(MIPS_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_STATIC) -o $@ $<

# MIPSEL targets
stack-hello-mipsel: $(MIPSEL_DIR)/hello_dyn $(MIPSEL_DIR)/hello_static

$(MIPSEL_DIR)/hello_dyn: $(SRC_FILE)
	@echo "Building MIPSEL dynamic binary..."
	$(MIPSEL_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_DYNAMIC) -o $@ $<

$(MIPSEL_DIR)/hello_static: $(SRC_FILE)
	@echo "Building MIPSEL static binary..."
	$(MIPSEL_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_STATIC) -o $@ $<

# PowerPC targets
stack-hello-ppc: $(PPC_DIR)/hello_dyn $(PPC_DIR)/hello_static

$(PPC_DIR)/hello_dyn: $(SRC_FILE)
	@echo "Building PowerPC dynamic binary..."
	$(PPC_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_DYNAMIC) -o $@ $<

$(PPC_DIR)/hello_static: $(SRC_FILE)
	@echo "Building PowerPC static binary..."
	$(PPC_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_STATIC) -o $@ $<

# RISC-V 32-bit targets
stack-hello-riscv32: $(RISCV32_DIR)/hello_dyn $(RISCV32_DIR)/hello_static

$(RISCV32_DIR)/hello_dyn: $(SRC_FILE)
	@echo "Building RISC-V 32-bit dynamic binary..."
	$(RISCV32_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_DYNAMIC) -o $@ $<

$(RISCV32_DIR)/hello_static: $(SRC_FILE)
	@echo "Building RISC-V 32-bit static binary..."
	$(RISCV32_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_STATIC) -o $@ $<

# RISC-V 64-bit targets
stack-hello-riscv64: $(RISCV64_DIR)/hello_dyn $(RISCV64_DIR)/hello_static

$(RISCV64_DIR)/hello_dyn: $(SRC_FILE)
	@echo "Building RISC-V 64-bit dynamic binary..."
	$(RISCV64_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_DYNAMIC) -o $@ $<

$(RISCV64_DIR)/hello_static: $(SRC_FILE)
	@echo "Building RISC-V 64-bit static binary..."
	$(RISCV64_TOOLCHAIN) $(CFLAGS) $(LDFLAGS_STATIC) -o $@ $<

# Clean targets
clean:
	@echo "Cleaning all binaries..."
	rm -f $(AARCH64_DIR)/hello_dyn $(AARCH64_DIR)/hello_static
	rm -f $(AARCH32_DIR)/hello_dyn $(AARCH32_DIR)/hello_static
	rm -f $(MIPS_DIR)/hello_dyn $(MIPS_DIR)/hello_static
	rm -f $(MIPSEL_DIR)/hello_dyn $(MIPSEL_DIR)/hello_static
	rm -f $(PPC_DIR)/hello_dyn $(PPC_DIR)/hello_static
	rm -f $(RISCV32_DIR)/hello_dyn $(RISCV32_DIR)/hello_static
	rm -f $(RISCV64_DIR)/hello_dyn $(RISCV64_DIR)/hello_static

# Help target
help:
	@echo "Available targets:"
	@echo "  all              - Build all architectures (same as stack-hello)"
	@echo "  stack-hello      - Build hello binaries for all architectures"
	@echo "  stack-hello-<arch> - Build hello binaries for specific architecture"
	@echo "                     Available architectures: aarch64, aarch32, mips, mipsel, ppc, riscv32, riscv64"
	@echo "  clean            - Remove all built binaries"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Example usage:"
	@echo "  make stack-hello          # Build for all architectures"
	@echo "  make stack-hello-aarch64  # Build only for AArch64"
	@echo "  make clean                # Clean all binaries"