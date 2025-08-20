# 工具链路径
TOOLCHAIN_DIR = toolchain

# 定义各架构的工具链
AARCH32_CC = $(TOOLCHAIN_DIR)/armv7-eabihf--glibc--stable-2018.11-1/bin/arm-buildroot-linux-gnueabihf-gcc
AARCH64_CC = $(TOOLCHAIN_DIR)/aarch64--glibc--stable-2018.11-1/bin/aarch64-buildroot-linux-gnu-gcc
MIPS32_CC = $(TOOLCHAIN_DIR)/mips-linux-musl-cross/bin/mips-linux-musl-gcc
MIPS64_CC = $(TOOLCHAIN_DIR)/mips64-linux-musl-cross/bin/mips64-linux-musl-gcc
RISCV32_CC = $(TOOLCHAIN_DIR)/riscv32-ilp32d--uclibc--stable-2024.05-1/bin/riscv32-buildroot-linux-uclibc-gcc
RISCV64_CC = $(TOOLCHAIN_DIR)/riscv64-lp64d--uclibc--stable-2024.05-1/bin/riscv64-buildroot-linux-uclibc-gcc

# 编译选项：启用所有保护（保护全开）
CFLAGS = -g -fstack-protector-all -pie -fPIE -z relro -z now -Wl,-z,noexecstack

# 源文件
AARCH32_SOURCES = $(wildcard src/iofile/*aarch32*.c)
AARCH64_SOURCES = $(wildcard src/iofile/*aarch64*.c)
MIPS32_SOURCES = $(wildcard src/iofile/*mips32*.c)
MIPS64_SOURCES = $(wildcard src/iofile/*mips64*.c)
RISCV32_SOURCES = $(wildcard src/iofile/*riscv32*.c)
RISCV64_SOURCES = $(wildcard src/iofile/*riscv64*.c)

# 默认目标
all: aarch32-build aarch64-build mips32-build mips64-build riscv32-build riscv64-build

# 创建目录并编译
aarch32-build:
	@mkdir -p aarch32/iofile
	$(AARCH32_CC) $(CFLAGS) $(AARCH32_SOURCES) -o aarch32/iofile/hello

aarch64-build:
	@mkdir -p aarch64/iofile
	$(AARCH64_CC) $(CFLAGS) $(AARCH64_SOURCES) -o aarch64/iofile/hello

mips32-build:
	@mkdir -p mips32/iofile
	$(MIPS32_CC) $(CFLAGS) $(MIPS32_SOURCES) -o mips32/iofile/hello

mips64-build:
	@mkdir -p mips64/iofile
	$(MIPS64_CC) $(CFLAGS) $(MIPS64_SOURCES) -o mips64/iofile/hello

riscv32-build:
	@mkdir -p riscv32/iofile
	$(RISCV32_CC) $(CFLAGS) $(RISCV32_SOURCES) -o riscv32/iofile/hello

riscv64-build:
	@mkdir -p riscv64/iofile
	$(RISCV64_CC) $(CFLAGS) $(RISCV64_SOURCES) -o riscv64/iofile/hello

# 便捷目标
aarch32: aarch32-build
aarch64: aarch64-build
mips32: mips32-build
mips64: mips64-build
riscv32: riscv32-build
riscv64: riscv64-build

# 清理
clean:
	rm -f aarch32/iofile/iofile aarch64/iofile/iofile mips32/iofile/iofile mips64/iofile/iofile riscv32/iofile/iofile riscv64/iofile/iofile

# 帮助
help:
	@echo "可用目标:"
	@echo "  all      - 编译所有架构"
	@echo "  aarch32  - 编译ARM 32位"
	@echo "  aarch64  - 编译ARM 64位"
	@echo "  mips32   - 编译MIPS 32位"
	@echo "  mips64   - 编译MIPS 64位"
	@echo "  riscv32  - 编译RISC-V 32位"
	@echo "  riscv64  - 编译RISC-V 64位"
	@echo "  clean    - 清理编译结果"

.PHONY: all aarch32 aarch64 mips32 mips64 riscv32 riscv64 clean help aarch32-build aarch64-build mips32-build mips64-build riscv32-build riscv64-build
