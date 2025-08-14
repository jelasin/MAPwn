############################################################
# Multi-architecture Makefile for HEAP 演示/利用二进制
# 与 stack.mk 不同：这里开启常见编译期 / 运行期保护 ("保护全开")
#
# 启用的保护：
#  - PIE:              位置无关可执行 (ASLR 充分)
#  - Stack Canary:     -fstack-protector-strong
#  - RELRO (Full):     -Wl,-z,relro,-z,now
#  - NX:               默认开启（确保没有可执行栈）
#  - Fortify:          -D_FORTIFY_SOURCE=2 (需要 -O2 及以上)
#  - 有调试符号:       -g
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

# 通用编译 / 链接选项 (保护全开)
# -fPIE / -pie: 生成 PIE
# -fstack-protector-strong: 强保护 (检查更多函数)
# -D_FORTIFY_SOURCE=2: Fortify 检查 (需要优化)
# -O2: 打开优化使 Fortify 生效，同时保留可调试性
# -Wl,-z,relro,-z,now: 全 RELRO (立即绑定)
# -Wl,-z,noexecstack: 确认 NX 栈
COMMON_CFLAGS  = -fPIE -fstack-protector-strong -O2 -g -D_FORTIFY_SOURCE=2
COMMON_LDFLAGS = -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie

# 目标名称 (与 stack.mk 保持类似风格)
heap_armv7   : aarch32/heap/heap
heap_aarch64 : aarch64/heap/heap
heap_mips    : mips/heap/heap
heap_mipsel  : mipsel/heap/heap
heap_ppc     : ppc/heap/heap
heap_rv32    : riscv32/heap/heap
heap_rv64    : riscv64/heap/heap

# =============== 各架构编译规则 ===============
# 期望源文件：src/heap/heap_<arch>.c
# 若暂不存在，可自行添加；当前仅提供 armv7 示例 (heap_armv7.c)

aarch32/heap/heap: src/heap/heap_armv7.c
	@echo "[ARMv7] Building protected heap binary..."
	@mkdir -p aarch32/heap
	$(ARMV7_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[ARMv7] Done: $@"

# 下面的规则若对应源文件缺失，会提示用户创建
aarch64/heap/heap: src/heap/heap_aarch64.c
	@echo "[AArch64] Building protected heap binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p aarch64/heap
	$(AARCH64_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[AArch64] Done: $@"

mips/heap/heap: src/heap/heap_mips.c
	@echo "[MIPS] Building protected heap binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p mips/heap
	$(MIPS_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[MIPS] Done: $@"

mipsel/heap/heap: src/heap/heap_mipsel.c
	@echo "[MIPSEL] Building protected heap binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p mipsel/heap
	$(MIPSEL_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[MIPSEL] Done: $@"

ppc/heap/heap: src/heap/heap_ppc.c
	@echo "[PPC] Building protected heap binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p ppc/heap
	$(PPC_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[PPC] Done: $@"

riscv32/heap/heap: src/heap/heap_rv32.c
	@echo "[RV32] Building protected heap binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p riscv32/heap
	$(RV32_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[RV32] Done: $@"

riscv64/heap/heap: src/heap/heap_rv64.c
	@echo "[RV64] Building protected heap binary..."
	@if [ ! -f $< ]; then echo "Source $< missing. Create it first."; exit 1; fi
	@mkdir -p riscv64/heap
	$(RV64_CC) $(COMMON_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)
	@echo "[RV64] Done: $@"

# =============== 信息展示函数 ===============
define show_binary_info
	@echo "=== Security info for $(1) ==="
	@if [ -f "$(1)" ]; then \
		file $(1); \
		echo "-- Canary:"; \
		$(2) -s $(1) | grep -E "__stack_chk_fail|__stack_chk_guard" >/dev/null 2>&1 && echo "  Stack canary PRESENT" || echo "  Stack canary NOT found (unexpected)"; \
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
	$(call show_binary_info,aarch32/heap/heap,$(ARMV7_READELF),$(ARMV7_OBJDUMP))
	$(call show_binary_info,aarch64/heap/heap,$(AARCH64_READELF),$(AARCH64_OBJDUMP))
	$(call show_binary_info,mips/heap/heap,$(MIPS_READELF),$(MIPS_OBJDUMP))
	$(call show_binary_info,mipsel/heap/heap,$(MIPSEL_READELF),$(MIPSEL_OBJDUMP))
	$(call show_binary_info,ppc/heap/heap,$(PPC_READELF),$(PPC_OBJDUMP))
	$(call show_binary_info,riscv32/heap/heap,$(RV32_READELF),$(RV32_OBJDUMP))
	$(call show_binary_info,riscv64/heap/heap,$(RV64_READELF),$(RV64_OBJDUMP))

# 一键编译（存在的源才能成功）
all: heap_armv7 heap_aarch64 heap_mips heap_mipsel heap_ppc heap_rv32 heap_rv64

# 清理
clean:
	@echo "Cleaning heap binaries..."
	@rm -f aarch32/heap/heap aarch64/heap/heap mips/heap/heap mipsel/heap/heap ppc/heap/heap riscv32/heap/heap riscv64/heap/heap
	@echo "Done."

help:
	@echo "Multi-architecture HEAP Makefile (protections ENABLED)"
	@echo "Targets:"
	@echo "  heap_armv7 / heap_aarch64 / heap_mips / heap_mipsel / heap_ppc / heap_rv32 / heap_rv64"
	@echo "  all          - build all (only succeeds where sources exist)"
	@echo "  clean        - remove built binaries"
	@echo "  info         - show security feature summary"
	@echo "Source naming convention: src/heap/heap_<arch>.c (e.g. heap_armv7.c)"
	@echo "Protections enabled: PIE, Stack Canary, Full RELRO, NX, Fortify"

.PHONY: heap_armv7 heap_aarch64 heap_mips heap_mipsel heap_ppc heap_rv32 heap_rv64 all clean info help
