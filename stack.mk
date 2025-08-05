# Multi-architecture Makefile for stack exploitation binaries
# 支持多架构编译，关闭 PIE 和 canary 保护

# 工具链配置
TOOLCHAIN_BASE = toolchain

# ARM v7 (32-bit) 工具链
ARMV7_TOOLCHAIN = $(TOOLCHAIN_BASE)/armv7-eabihf--glibc--stable-2024.05-1
ARMV7_CC = $(ARMV7_TOOLCHAIN)/bin/arm-buildroot-linux-gnueabihf-gcc
ARMV7_READELF = $(ARMV7_TOOLCHAIN)/bin/arm-buildroot-linux-gnueabihf-readelf
ARMV7_OBJDUMP = $(ARMV7_TOOLCHAIN)/bin/arm-buildroot-linux-gnueabihf-objdump

# ARM v8 (64-bit) 工具链
AARCH64_TOOLCHAIN = $(TOOLCHAIN_BASE)/aarch64--glibc--stable-2024.05-1
AARCH64_CC = $(AARCH64_TOOLCHAIN)/bin/aarch64-buildroot-linux-gnu-gcc
AARCH64_READELF = $(AARCH64_TOOLCHAIN)/bin/aarch64-buildroot-linux-gnu-readelf
AARCH64_OBJDUMP = $(AARCH64_TOOLCHAIN)/bin/aarch64-buildroot-linux-gnu-objdump

# MIPS (32-bit big endian) 工具链
MIPS_TOOLCHAIN = $(TOOLCHAIN_BASE)/mips32--glibc--stable-2024.05-1
MIPS_CC = $(MIPS_TOOLCHAIN)/bin/mips-buildroot-linux-gnu-gcc
MIPS_READELF = $(MIPS_TOOLCHAIN)/bin/mips-buildroot-linux-gnu-readelf
MIPS_OBJDUMP = $(MIPS_TOOLCHAIN)/bin/mips-buildroot-linux-gnu-objdump

# MIPS (32-bit little endian) 工具链
MIPSEL_TOOLCHAIN = $(TOOLCHAIN_BASE)/mips32el--glibc--stable-2024.05-1
MIPSEL_CC = $(MIPSEL_TOOLCHAIN)/bin/mipsel-buildroot-linux-gnu-gcc
MIPSEL_READELF = $(MIPSEL_TOOLCHAIN)/bin/mipsel-buildroot-linux-gnu-readelf
MIPSEL_OBJDUMP = $(MIPSEL_TOOLCHAIN)/bin/mipsel-buildroot-linux-gnu-objdump

# PowerPC 工具链
PPC_TOOLCHAIN = $(TOOLCHAIN_BASE)/powerpc-440fp--glibc--stable-2024.05-1
PPC_CC = $(PPC_TOOLCHAIN)/bin/powerpc-buildroot-linux-gnu-gcc
PPC_READELF = $(PPC_TOOLCHAIN)/bin/powerpc-buildroot-linux-gnu-readelf
PPC_OBJDUMP = $(PPC_TOOLCHAIN)/bin/powerpc-buildroot-linux-gnu-objdump

# RISC-V 32-bit 工具链
RV32_TOOLCHAIN = $(TOOLCHAIN_BASE)/riscv32-ilp32d--glibc--stable-2024.05-1
RV32_CC = $(RV32_TOOLCHAIN)/bin/riscv32-buildroot-linux-gnu-gcc
RV32_READELF = $(RV32_TOOLCHAIN)/bin/riscv32-buildroot-linux-gnu-readelf
RV32_OBJDUMP = $(RV32_TOOLCHAIN)/bin/riscv32-buildroot-linux-gnu-objdump

# RISC-V 64-bit 工具链
RV64_TOOLCHAIN = $(TOOLCHAIN_BASE)/riscv64-lp64d--glibc--stable-2024.05-1
RV64_CC = $(RV64_TOOLCHAIN)/bin/riscv64-buildroot-linux-gnu-gcc
RV64_READELF = $(RV64_TOOLCHAIN)/bin/riscv64-buildroot-linux-gnu-readelf
RV64_OBJDUMP = $(RV64_TOOLCHAIN)/bin/riscv64-buildroot-linux-gnu-objdump

# 通用编译选项
# -fno-pie: 关闭 PIE (Position Independent Executable)
# -no-pie: 关闭 PIE 链接选项
# -fno-stack-protector: 关闭 stack canary 保护
# -O0: 关闭优化，便于调试
# -g: 包含调试信息
COMMON_CFLAGS = -fno-pie -no-pie -fno-stack-protector -O0 -g

# 架构特定目标
hello_armv7: aarch32/stack/hello
hello_aarch64: aarch64/stack/hello
hello_mips: mips/stack/hello
hello_mipsel: mipsel/stack/hello
hello_ppc: ppc/stack/hello
hello_rv32: riscv32/stack/hello
hello_rv64: riscv64/stack/hello

# ARM v7 编译规则
aarch32/stack/hello: src/stack/hello_armv7.c
	@echo "Compiling for ARM v7 (32-bit)..."
	@mkdir -p aarch32/stack
	$(ARMV7_CC) $(COMMON_CFLAGS) -o $@ $<
	@echo "ARM v7 compilation successful: $@"

# ARM v8 (AArch64) 编译规则
aarch64/stack/hello: src/stack/hello_aarch64.c
	@echo "Compiling for ARM v8 (64-bit)..."
	@mkdir -p aarch64/stack
	$(AARCH64_CC) $(COMMON_CFLAGS) -o $@ $<
	@echo "AArch64 compilation successful: $@"

# MIPS 编译规则
mips/stack/hello: src/stack/hello_mips.c
	@echo "Compiling for MIPS (32-bit big endian)..."
	@mkdir -p mips/stack
	$(MIPS_CC) $(COMMON_CFLAGS) -o $@ $<
	@echo "MIPS compilation successful: $@"

# MIPS Little Endian 编译规则
mipsel/stack/hello: src/stack/hello_mipsel.c
	@echo "Compiling for MIPS (32-bit little endian)..."
	@mkdir -p mipsel/stack
	$(MIPSEL_CC) $(COMMON_CFLAGS) -o $@ $<
	@echo "MIPSEL compilation successful: $@"

# PowerPC 编译规则
ppc/stack/hello: src/stack/hello_ppc.c
	@echo "Compiling for PowerPC..."
	@mkdir -p ppc/stack
	$(PPC_CC) $(COMMON_CFLAGS) -o $@ $<
	@echo "PowerPC compilation successful: $@"

# RISC-V 32-bit 编译规则
riscv32/stack/hello: src/stack/hello_rv32.c
	@echo "Compiling for RISC-V 32-bit..."
	@mkdir -p riscv32/stack
	$(RV32_CC) $(COMMON_CFLAGS) -o $@ $<
	@echo "RISC-V 32-bit compilation successful: $@"

# RISC-V 64-bit 编译规则
riscv64/stack/hello: src/stack/hello_rv64.c
	@echo "Compiling for RISC-V 64-bit..."
	@mkdir -p riscv64/stack
	$(RV64_CC) $(COMMON_CFLAGS) -o $@ $<
	@echo "RISC-V 64-bit compilation successful: $@"

# 清理所有目标
clean:
	@echo "Cleaning all stack binaries..."
	@rm -f aarch32/stack/hello
	@rm -f aarch64/stack/hello
	@rm -f mips/stack/hello
	@rm -f mipsel/stack/hello
	@rm -f ppc/stack/hello
	@rm -f riscv32/stack/hello
	@rm -f riscv64/stack/hello
	@echo "Clean complete"

# 编译所有架构
all: hello_armv7 hello_aarch64 hello_mips hello_mipsel hello_ppc hello_rv32 hello_rv64

# 二进制文件信息函数
define show_binary_info
	@echo "=== Binary information for $(1) ==="
	@if [ -f "$(1)" ]; then \
		file $(1); \
		echo "Security features:"; \
		$(2) -h $(1) | grep -E "(Type|Entry)" || true; \
		echo "Checking for stack canary and PIE:"; \
		$(3) -t $(1) | grep -E "(stack_chk|__stack_chk)" >/dev/null 2>&1 && echo "Stack canary detected (bad)" || echo "No stack canary found (good)"; \
		$(2) -h $(1) | grep "Type:" | grep -q "EXEC" && echo "PIE disabled (good)" || echo "PIE may be enabled"; \
	else \
		echo "Binary $(1) not found. Run the corresponding target first."; \
	fi
	@echo ""
endef

# 显示各架构二进制文件信息
info:
	$(call show_binary_info,aarch32/stack/hello,$(ARMV7_READELF),$(ARMV7_OBJDUMP))
	$(call show_binary_info,aarch64/stack/hello,$(AARCH64_READELF),$(AARCH64_OBJDUMP))
	$(call show_binary_info,mips/stack/hello,$(MIPS_READELF),$(MIPS_OBJDUMP))
	$(call show_binary_info,mipsel/stack/hello,$(MIPSEL_READELF),$(MIPSEL_OBJDUMP))
	$(call show_binary_info,ppc/stack/hello,$(PPC_READELF),$(PPC_OBJDUMP))
	$(call show_binary_info,riscv32/stack/hello,$(RV32_READELF),$(RV32_OBJDUMP))
	$(call show_binary_info,riscv64/stack/hello,$(RV64_READELF),$(RV64_OBJDUMP))

# 帮助信息
help:
	@echo "Multi-architecture Stack Exploitation Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  hello_armv7   - Compile for ARM v7 (32-bit)"
	@echo "  hello_aarch64 - Compile for ARM v8 (64-bit)"
	@echo "  hello_mips    - Compile for MIPS (32-bit big endian)"
	@echo "  hello_mipsel  - Compile for MIPS (32-bit little endian)"
	@echo "  hello_ppc     - Compile for PowerPC"
	@echo "  hello_rv32    - Compile for RISC-V 32-bit"
	@echo "  hello_rv64    - Compile for RISC-V 64-bit"
	@echo "  all           - Compile for all architectures"
	@echo "  clean         - Remove all compiled binaries"
	@echo "  info          - Show binary information and security features"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Source files expected:"
	@echo "  src/stack/hello_armv7.c   (exists)"
	@echo "  src/stack/hello_aarch64.c (exists)"
	@echo "  src/stack/hello_mips.c    (exists)"
	@echo "  src/stack/hello_mipsel.c  (exists)"
	@echo "  src/stack/hello_ppc.c     (exists)"
	@echo "  src/stack/hello_rv32.c    (exists)"
	@echo "  src/stack/hello_rv64.c    (exists)"

.PHONY: hello_armv7 hello_aarch64 hello_mips hello_mipsel hello_ppc hello_rv32 hello_rv64 all clean info help