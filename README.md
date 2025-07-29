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
# 工具链
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

## stack

```bash
make -f stack.mk all
```

会在每个架构目录下对应子目录生成动态链接和静态链接两个文件。
