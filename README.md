# 环境准备

* ubuntu 24.04-WSL2
* qemu-10.0.2
* 交叉编译工具链: **[toolchains-bootlin](https://toolchains.bootlin.com/toolchains.html)**

```bash
# 目录结构
➜  MAPwn git:(master) ✗ ls -lh
total 40K
-rw-r--r-- 1 ub24 ub24  753 Jul 29 18:23 README.md
drwxr-xr-x 6 ub24 ub24 4.0K Jul 29 17:44 aarch32
drwxr-xr-x 6 ub24 ub24 4.0K Jul 29 17:44 aarch64
-rw-r--r-- 1 ub24 ub24    0 Jul 29 18:24 makefile
drwxr-xr-x 6 ub24 ub24 4.0K Jul 29 17:44 mips
drwxr-xr-x 6 ub24 ub24 4.0K Jul 29 17:44 mipsel
drwxr-xr-x 6 ub24 ub24 4.0K Jul 29 17:44 ppc
drwxr-xr-x 6 ub24 ub24 4.0K Jul 29 17:44 riscv32
drwxr-xr-x 6 ub24 ub24 4.0K Jul 29 17:44 riscv64
drwxr-xr-x 6 ub24 ub24 4.0K Jul 29 17:43 src
drwxr-xr-x 9 ub24 ub24 4.0K Jul 29 18:20 toolchain
# 工具链 glibc-2.39
➜  toolchain git:(master) ✗ ls -lh 
total 28K
drwxr-xr-x 9 ub24 ub24 4.0K Aug 17  2024 aarch64--glibc--stable-2024.05-1
drwxr-xr-x 9 ub24 ub24 4.0K Aug 17  2024 armv7-eabihf--glibc--stable-2024.05-1
drwxr-xr-x 9 ub24 ub24 4.0K Aug 17  2024 mips32--glibc--stable-2024.05-1
drwxr-xr-x 9 ub24 ub24 4.0K Aug 17  2024 mips32el--glibc--stable-2024.05-1
drwxr-xr-x 9 ub24 ub24 4.0K Aug 17  2024 powerpc-440fp--glibc--stable-2024.05-1
drwxr-xr-x 9 ub24 ub24 4.0K Aug 18  2024 riscv32-ilp32d--glibc--stable-2024.05-1
drwxr-xr-x 9 ub24 ub24 4.0K Aug 18  2024 riscv64-lp64d--glibc--stable-2024.05-1
```

需要将交叉编译工具链放在项目根目录下, 各架构下的lib目录才能软连接到对应的sysroot。

以armv7-eabihf为例:

```text
➜  stack git:(master) ✗ ls -lh
total 40K
-rw-r--r-- 1 ub24 ub24  14K Jul 30 16:18 README.md
-rw-r--r-- 1 ub24 ub24 1.1K Jul 30 17:56 exp.py
-rwxr-xr-x 1 ub24 ub24   84 Jul 30 17:17 gdb.sh
-rwxr-xr-x 1 ub24 ub24  12K Jul 30 17:51 hello
lrwxrwxrwx 1 ub24 ub24   91 Jul 30 17:56 lib -> ../../toolchain/armv7-eabihf--glibc--stable-2024.05-1/arm-buildroot-linux-gnueabihf/sysroot
```

## stack

arch 取值为 `armv7`, `aarch64`, `mips`, `mipsel`, `ppc`, `rv32`, `rv64`。

其中 armv7 为对应 aarch32 的子目录。

```bash
make -f stack.mk {arch}
```
