############################################################
# Multi-architecture Makefile for IOFILE 演示/利用二进制
# 保护全开版本 (Full RELRO)
#
# 启用的保护：
#  - PIE:              -fPIE / -pie
#  - Stack Canary:     -fstack-protector-strong
#  - RELRO (Full):     -Wl,-z,relro,-z,now
#  - NX:               -Wl,-z,noexecstack (确保非可执行栈)
#  - Fortify:          -D_FORTIFY_SOURCE=2 (需 -O2)
#  - 调试符号:         -g
############################################################

# 工具链根目录
TOOLCHAIN_BASE = toolchain

# ARM v7 (32-bit)
ARMV7_TOOLCHAIN = $(TOOLCHAIN_BASE)/armv7-eabihf--glibc--stable-2024.05-1
ARMV7_CC       = $(ARMV7_TOOLCHAIN)/bin/arm-buildroot-linux-gnueabihf-gcc
ARMV7_READELF  = $(ARMV7_TOOLCHAIN)/bin/arm-buildroot-linux-gnueabihf-readelf
ARMV7_OBJDUMP  = $(ARMV7_TOOLCHAIN)/bin/arm-buildroot-linux-gnueabihf-objdump

# ARM v8 (AArch64)
AARCH64_TOOLCHAIN = $(TOOLCHAIN_BASE)/aarch64--glibc--stable-2024.05-1
AARCH64_CC       = $(AARCH64_TOOLCHAIN)/bin/aarch64-buildroot-linux-gnu-gcc
AARCH64_READELF  = $(AARCH64_TOOLCHAIN)/bin/aarch64-buildroot-linux-gnu-readelf
AARCH64_OBJDUMP  = $(AARCH64_TOOLCHAIN)/bin/aarch64-buildroot-linux-gnu-objdump

# MIPS (32-bit big endian)
MIPS_TOOLCHAIN = $(TOOLCHAIN_BASE)/mips32--glibc--stable-2024.05-1
MIPS_CC       = $(MIPS_TOOLCHAIN)/bin/mips-buildroot-linux-gnu-gcc
MIPS_READELF  = $(MIPS_TOOLCHAIN)/bin/mips-buildroot-linux-gnu-readelf
MIPS_OBJDUMP  = $(MIPS_TOOLCHAIN)/bin/mips-buildroot-linux-gnu-objdump

# MIPS (32-bit little endian)
MIPSEL_TOOLCHAIN = $(TOOLCHAIN_BASE)/mips32el--glibc--stable-2024.05-1
MIPSEL_CC       = $(MIPSEL_TOOLCHAIN)/bin/mipsel-buildroot-linux-gnu-gcc
MIPSEL_READELF  = $(MIPSEL_TOOLCHAIN)/bin/mipsel-buildroot-linux-gnu-readelf
MIPSEL_OBJDUMP  = $(MIPSEL_TOOLCHAIN)/bin/mipsel-buildroot-linux-gnu-objdump

# PowerPC
PPC_TOOLCHAIN = $(TOOLCHAIN_BASE)/powerpc-440fp--glibc--stable-2024.05-1
PPC_CC       = $(PPC_TOOLCHAIN)/bin/powerpc-buildroot-linux-gnu-gcc
PPC_READELF  = $(PPC_TOOLCHAIN)/bin/powerpc-buildroot-linux-gnu-readelf
PPC_OBJDUMP  = $(PPC_TOOLCHAIN)/bin/powerpc-buildroot-linux-gnu-objdump

# RISC-V 32-bit
RV32_TOOLCHAIN = $(TOOLCHAIN_BASE)/riscv32-ilp32d--glibc--stable-2024.05-1
RV32_CC       = $(RV32_TOOLCHAIN)/bin/riscv32-buildroot-linux-gnu-gcc
RV32_READELF  = $(RV32_TOOLCHAIN)/bin/riscv32-buildroot-linux-gnu-readelf
RV32_OBJDUMP  = $(RV32_TOOLCHAIN)/bin/riscv32-buildroot-linux-gnu-objdump

# RISC-V 64-bit
RV64_TOOLCHAIN = $(TOOLCHAIN_BASE)/riscv64-lp64d--glibc--stable-2024.05-1
RV64_CC       = $(RV64_TOOLCHAIN)/bin/riscv64-buildroot-linux-gnu-gcc
RV64_READELF  = $(RV64_TOOLCHAIN)/bin/riscv64-buildroot-linux-gnu-readelf
RV64_OBJDUMP  = $(RV64_TOOLCHAIN)/bin/riscv64-buildroot-linux-gnu-objdump

# 通用编译 / 链接选项 (Full RELRO)
COMMON_CFLAGS  = -fPIE -fstack-protector-strong -O2 -g -D_FORTIFY_SOURCE=2
COMMON_LDFLAGS = -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie

# 目标名称
iofile_armv7   : aarch32/iofile/iofile
iofile_aarch64 : aarch64/iofile/iofile
iofile_mips    : mips/iofile/iofile
iofile_mipsel  : mipsel/iofile/iofile
iofile_ppc     : ppc/iofile/iofile
iofile_rv32    : riscv32/iofile/iofile
iofile_rv64    : riscv64/iofile/iofile

# =============== 各架构编译规则 ===============
# 源文件约定: src/iofile/iofile_<arch>.c  (示例: iofile_armv7.c)

aarch32/iofile/iofile: src/iofile/iofile_armv7.c
	@echo "[ARMv7] Building FULL RELRO iofile binary..."
	@mkdir -p aarch32/iofile
	$(ARMV7_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[ARMv7] Done: $@"

aarch64/iofile/iofile: src/iofile/iofile_aarch64.c
	@echo "[AArch64] Building FULL RELRO iofile binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p aarch64/iofile
	$(AARCH64_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[AArch64] Done: $@"

mips/iofile/iofile: src/iofile/iofile_mips.c
	@echo "[MIPS] Building FULL RELRO iofile binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p mips/iofile
	$(MIPS_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[MIPS] Done: $@"

mipsel/iofile/iofile: src/iofile/iofile_mipsel.c
	@echo "[MIPSEL] Building FULL RELRO iofile binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p mipsel/iofile
	$(MIPSEL_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[MIPSEL] Done: $@"

ppc/iofile/iofile: src/iofile/iofile_ppc.c
	@echo "[PPC] Building FULL RELRO iofile binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p ppc/iofile
	$(PPC_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[PPC] Done: $@"

riscv32/iofile/iofile: src/iofile/iofile_rv32.c
	@echo "[RV32] Building FULL RELRO iofile binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p riscv32/iofile
	$(RV32_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[RV32] Done: $@"

riscv64/iofile/iofile: src/iofile/iofile_rv64.c
	@echo "[RV64] Building FULL RELRO iofile binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p riscv64/iofile
	$(RV64_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[RV64] Done: $@"

# =============== 信息展示函数 ===============
define show_binary_info
	@echo "=== Security info for $(1) ==="
	@if [ -f "$(1)" ]; then \
		file $(1); \
		echo "-- Canary:"; \
		$(2) -s $(1) | grep -E "__stack_chk_fail|__stack_chk_guard" >/dev/null 2>&1 && echo "  Stack canary PRESENT" || echo "  Stack canary NOT found"; \
		echo "-- PIE:"; \
		$(2) -h $(1) | grep "Type:" | grep -q DYN && echo "  PIE enabled (DYN)" || echo "  Not PIE"; \
		echo "-- RELRO:"; \
		($(2) -l $(1) | grep -q GNU_RELRO && $(2) -d $(1) | grep -q BIND_NOW) && echo "  Full RELRO" || ( $(2) -l $(1) | grep -q GNU_RELRO && echo "  Partial RELRO" || echo "  No RELRO" ); \
		echo "-- NX (non-exec stack):"; \
		$(2) -W -l $(1) | grep GNU_STACK | grep -q "RWE" && echo "  Executable stack (BAD)" || echo "  Non-exec stack (GOOD)"; \
		echo "-- Fortify symbols:"; \
		$(3) -t $(1) | grep -E "__fprintf_chk|__memcpy_chk|__memmove_chk|__printf_chk|__snprintf_chk|__strcpy_chk" >/dev/null 2>&1 && echo "  Fortify in use" || echo "  Fortify not detected"; \
	else \
		echo "Binary $(1) not found."; \
	fi
	@echo ""
endef

info:
	$(call show_binary_info,aarch32/iofile/iofile,$(ARMV7_READELF),$(ARMV7_OBJDUMP))
	$(call show_binary_info,aarch64/iofile/iofile,$(AARCH64_READELF),$(AARCH64_OBJDUMP))
	$(call show_binary_info,mips/iofile/iofile,$(MIPS_READELF),$(MIPS_OBJDUMP))
	$(call show_binary_info,mipsel/iofile/iofile,$(MIPSEL_READELF),$(MIPSEL_OBJDUMP))
	$(call show_binary_info,ppc/iofile/iofile,$(PPC_READELF),$(PPC_OBJDUMP))
	$(call show_binary_info,riscv32/iofile/iofile,$(RV32_READELF),$(RV32_OBJDUMP))
	$(call show_binary_info,riscv64/iofile/iofile,$(RV64_READELF),$(RV64_OBJDUMP))

# 一键编译（存在的源才能成功）
all: iofile_armv7 iofile_aarch64 iofile_mips iofile_mipsel iofile_ppc iofile_rv32 iofile_rv64

clean:
	@echo "Cleaning iofile binaries..."
	@rm -f aarch32/iofile/iofile aarch64/iofile/iofile mips/iofile/iofile mipsel/iofile/iofile ppc/iofile/iofile riscv32/iofile/iofile riscv64/iofile/iofile
	@echo "Done."

help:
	@echo "Multi-architecture IOFILE Makefile (Full protections)"
	@echo "Targets:"
	@echo "  iofile_armv7 / iofile_aarch64 / iofile_mips / iofile_mipsel / iofile_ppc / iofile_rv32 / iofile_rv64"
	@echo "  all          - build all (only succeeds where sources exist)"
	@echo "  clean        - remove built binaries"
	@echo "  info         - show security feature summary"
	@echo "Source naming: src/iofile/iofile_<arch>.c"
	@echo "Protections enabled: PIE, Stack Canary, Full RELRO, NX, Fortify"

.PHONY: iofile_armv7 iofile_aarch64 iofile_mips iofile_mipsel iofile_ppc iofile_rv32 iofile_rv64 all clean info help
