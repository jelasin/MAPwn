# AArch64 架构基础知识

## AArch64 寄存器详解

### 通用寄存器 (X0-X30, W0-W30)

```text
X0-X7    : 参数寄存器 / 返回值寄存器 (64位)
W0-W7    : 参数寄存器 / 返回值寄存器 (32位)
X8       : 间接结果位置寄存器
X9-X15   : 临时寄存器 (调用者保存)
X16-X17  : 程序内调用临时寄存器 (IP0, IP1)
X18      : 平台寄存器 (保留)
X19-X28  : 被调用者保存寄存器
X29      : 帧指针 (FP - Frame Pointer)
X30      : 链接寄存器 (LR - Link Register)
SP       : 栈指针 (Stack Pointer)
PC       : 程序计数器 (Program Counter)
```

### 寄存器详细用途

```text
寄存器  别名  用途                      调用约定         大小
X0      -     第1个参数/返回值          调用者保存       64位
X1      -     第2个参数/第2个返回值     调用者保存       64位
X2      -     第3个参数                调用者保存       64位
X3      -     第4个参数                调用者保存       64位
X4      -     第5个参数                调用者保存       64位
X5      -     第6个参数                调用者保存       64位
X6      -     第7个参数                调用者保存       64位
X7      -     第8个参数                调用者保存       64位
X8      -     间接结果位置              调用者保存       64位
X9-X15  -     临时寄存器               调用者保存       64位
X16     IP0   程序内调用临时寄存器     调用者保存       64位
X17     IP1   程序内调用临时寄存器     调用者保存       64位
X18     -     平台寄存器               保留             64位
X19-X28 -     被调用者保存寄存器       被调用者保存     64位
X29     FP    帧指针                   被调用者保存     64位
X30     LR    链接寄存器               特殊             64位
SP      -     栈指针                   N/A              64位
PC      -     程序计数器               N/A              64位
```

### W寄存器 (32位视图)

```text
W0-W30  : X0-X30的低32位视图
写入W寄存器会自动清零对应X寄存器的高32位
读取W寄存器只访问X寄存器的低32位
```

### SIMD/浮点寄存器

```text
V0-V31   : 128位SIMD/浮点寄存器
D0-D31   : V0-V31的64位视图 (双精度浮点)
S0-S31   : V0-V31的32位视图 (单精度浮点)
H0-H31   : V0-V31的16位视图 (半精度浮点)
B0-B31   : V0-V31的8位视图
```

### 特殊寄存器

```text
NZCV     : 条件标志寄存器 (Negative, Zero, Carry, oVerflow)
FPCR     : 浮点控制寄存器
FPSR     : 浮点状态寄存器
TPIDR_EL0: 用户态线程标识寄存器
```

## Linux AArch64 系统调用表

### 常用系统调用号

```c
#define __NR_io_setup                   0
#define __NR_io_destroy                 1
#define __NR_io_submit                  2
#define __NR_io_cancel                  3
#define __NR_io_getevents               4
#define __NR_setxattr                   5
#define __NR_lsetxattr                  6
#define __NR_fsetxattr                  7
#define __NR_getxattr                   8
#define __NR_lgetxattr                  9
#define __NR_fgetxattr                  10
#define __NR_listxattr                  11
#define __NR_llistxattr                 12
#define __NR_flistxattr                 13
#define __NR_removexattr                14
#define __NR_lremovexattr               15
#define __NR_fremovexattr               16
#define __NR_getcwd                     17
#define __NR_lookup_dcookie             18
#define __NR_eventfd2                   19
#define __NR_epoll_create1              20
#define __NR_epoll_ctl                  21
#define __NR_epoll_pwait                22
#define __NR_dup                        23
#define __NR_dup3                       24
#define __NR_fcntl                      25
#define __NR_inotify_init1              26
#define __NR_inotify_add_watch          27
#define __NR_inotify_rm_watch           28
#define __NR_ioctl                      29
#define __NR_ioprio_set                 30
#define __NR_ioprio_get                 31
#define __NR_flock                      32
#define __NR_mknodat                    33
#define __NR_mkdirat                    34
#define __NR_unlinkat                   35
#define __NR_symlinkat                  36
#define __NR_linkat                     37
#define __NR_renameat                   38
#define __NR_umount2                    39
#define __NR_mount                      40
#define __NR_pivot_root                 41
#define __NR_nfsservctl                 42
#define __NR_statfs                     43
#define __NR_fstatfs                    44
#define __NR_truncate                   45
#define __NR_ftruncate                  46
#define __NR_fallocate                  47
#define __NR_faccessat                  48
#define __NR_chdir                      49
#define __NR_fchdir                     50
#define __NR_chroot                     51
#define __NR_fchmod                     52
#define __NR_fchmodat                   53
#define __NR_fchownat                   54
#define __NR_fchown                     55
#define __NR_openat                     56
#define __NR_close                      57
#define __NR_vhangup                    58
#define __NR_pipe2                      59
#define __NR_quotactl                   60
#define __NR_getdents64                 61
#define __NR_lseek                      62
#define __NR_read                       63
#define __NR_write                      64
#define __NR_readv                      65
#define __NR_writev                     66
#define __NR_pread64                    67
#define __NR_pwrite64                   68
#define __NR_preadv                     69
#define __NR_pwritev                    70
#define __NR_sendfile                   71
#define __NR_pselect6                   72
#define __NR_ppoll                      73
#define __NR_signalfd4                  74
#define __NR_vmsplice                   75
#define __NR_splice                     76
#define __NR_tee                        77
#define __NR_readlinkat                 78
#define __NR_fstatat                    79
#define __NR_fstat                      80
#define __NR_sync                       81
#define __NR_fsync                      82
#define __NR_fdatasync                  83
#define __NR_sync_file_range            84
#define __NR_timerfd_create             85
#define __NR_timerfd_settime            86
#define __NR_timerfd_gettime            87
#define __NR_utimensat                  88
#define __NR_acct                       89
#define __NR_capget                     90
#define __NR_capset                     91
#define __NR_personality                92
#define __NR_exit                       93
#define __NR_exit_group                 94
#define __NR_waitid                     95
#define __NR_set_tid_address            96
#define __NR_unshare                    97
#define __NR_futex                      98
#define __NR_set_robust_list            99
#define __NR_get_robust_list            100
#define __NR_nanosleep                  101
#define __NR_getitimer                  102
#define __NR_setitimer                  103
#define __NR_kexec_load                 104
#define __NR_init_module                105
#define __NR_delete_module              106
#define __NR_timer_create               107
#define __NR_timer_gettime              108
#define __NR_timer_getoverrun           109
#define __NR_timer_settime              110
#define __NR_timer_delete               111
#define __NR_clock_settime              112
#define __NR_clock_gettime              113
#define __NR_clock_getres               114
#define __NR_clock_nanosleep            115
#define __NR_syslog                     116
#define __NR_ptrace                     117
#define __NR_sched_setparam             118
#define __NR_sched_setscheduler         119
#define __NR_sched_getscheduler         120
#define __NR_sched_getparam             121
#define __NR_sched_setaffinity          122
#define __NR_sched_getaffinity          123
#define __NR_sched_yield                124
#define __NR_sched_get_priority_max     125
#define __NR_sched_get_priority_min     126
#define __NR_sched_rr_get_interval      127
#define __NR_restart_syscall            128
#define __NR_kill                       129
#define __NR_tkill                      130
#define __NR_tgkill                     131
#define __NR_sigaltstack                132
#define __NR_rt_sigsuspend              133
#define __NR_rt_sigaction               134
#define __NR_rt_sigprocmask             135
#define __NR_rt_sigpending              136
#define __NR_rt_sigtimedwait            137
#define __NR_rt_sigqueueinfo            138
#define __NR_rt_sigreturn               139
#define __NR_setpriority                140
#define __NR_getpriority                141
#define __NR_reboot                     142
#define __NR_setregid                   143
#define __NR_setgid                     144
#define __NR_setreuid                   145
#define __NR_setuid                     146
#define __NR_setresuid                  147
#define __NR_getresuid                  148
#define __NR_setresgid                  149
#define __NR_getresgid                  150
#define __NR_setfsuid                   151
#define __NR_setfsgid                   152
#define __NR_times                      153
#define __NR_setpgid                    154
#define __NR_getpgid                    155
#define __NR_getsid                     156
#define __NR_setsid                     157
#define __NR_getgroups                  158
#define __NR_setgroups                  159
#define __NR_uname                      160
#define __NR_sethostname                161
#define __NR_setdomainname              162
#define __NR_getrlimit                  163
#define __NR_setrlimit                  164
#define __NR_getrusage                  165
#define __NR_umask                      166
#define __NR_prctl                      167
#define __NR_getcpu                     168
#define __NR_gettimeofday               169
#define __NR_settimeofday               170
#define __NR_adjtimex                   171
#define __NR_getpid                     172
#define __NR_getppid                    173
#define __NR_getuid                     174
#define __NR_geteuid                    175
#define __NR_getgid                     176
#define __NR_getegid                    177
#define __NR_gettid                     178
#define __NR_sysinfo                    179
#define __NR_mq_open                    180
#define __NR_mq_unlink                  181
#define __NR_mq_timedsend               182
#define __NR_mq_timedreceive            183
#define __NR_mq_notify                  184
#define __NR_mq_getsetattr              185
#define __NR_msgget                     186
#define __NR_msgctl                     187
#define __NR_msgrcv                     188
#define __NR_msgsnd                     189
#define __NR_semget                     190
#define __NR_semctl                     191
#define __NR_semtimedop                 192
#define __NR_semop                      193
#define __NR_shmget                     194
#define __NR_shmctl                     195
#define __NR_shmat                      196
#define __NR_shmdt                      197
#define __NR_socket                     198
#define __NR_socketpair                 199
#define __NR_bind                       200
#define __NR_listen                     201
#define __NR_accept                     202
#define __NR_connect                    203
#define __NR_getsockname                204
#define __NR_getpeername                205
#define __NR_sendto                     206
#define __NR_recvfrom                   207
#define __NR_setsockopt                 208
#define __NR_getsockopt                 209
#define __NR_shutdown                   210
#define __NR_sendmsg                    211
#define __NR_recvmsg                    212
#define __NR_readahead                  213
#define __NR_brk                        214
#define __NR_munmap                     215
#define __NR_mremap                     216
#define __NR_add_key                    217
#define __NR_request_key                218
#define __NR_keyctl                     219
#define __NR_clone                      220
#define __NR_execve                     221
#define __NR_mmap                       222
#define __NR_fadvise64                  223
#define __NR_swapon                     224
#define __NR_swapoff                    225
#define __NR_mprotect                   226
#define __NR_msync                      227
#define __NR_mlock                      228
#define __NR_munlock                    229
#define __NR_mlockall                   230
#define __NR_munlockall                 231
#define __NR_mincore                    232
#define __NR_madvise                    233
#define __NR_remap_file_pages           234
#define __NR_mbind                      235
#define __NR_get_mempolicy              236
#define __NR_set_mempolicy              237
#define __NR_migrate_pages              238
#define __NR_move_pages                 239
#define __NR_rt_tgsigqueueinfo          240
#define __NR_perf_event_open            241
#define __NR_accept4                    242
#define __NR_recvmmsg                   243
#define __NR_wait4                      260
#define __NR_prlimit64                  261
#define __NR_fanotify_init              262
#define __NR_fanotify_mark              263
#define __NR_name_to_handle_at          264
#define __NR_open_by_handle_at          265
#define __NR_clock_adjtime              266
#define __NR_syncfs                     267
#define __NR_setns                      268
#define __NR_sendmmsg                   269
#define __NR_process_vm_readv           270
#define __NR_process_vm_writev          271
#define __NR_kcmp                       272
#define __NR_finit_module               273
#define __NR_sched_setattr              274
#define __NR_sched_getattr              275
```

### 系统调用约定

[系统调用查询](https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html)

```text
系统调用号：x8
参数1-6：  x0, x1, x2, x3, x4, x5
返回值：    x0
调用指令：  svc #0 (Supervisor Call)
```

### 系统调用示例

```assembly
// write(1, "Hello", 5)
mov x0, #1          // fd = 1 (stdout)
adr x1, hello_str   // buf = "Hello"
mov x2, #5          // count = 5
mov x8, #64         // __NR_write
svc #0              // 系统调用

// exit(0)
mov x0, #0          // status = 0
mov x8, #93         // __NR_exit
svc #0
```

## 函数调用约定 (AAPCS64)

### 参数传递

```text
前8个整数参数：x0-x7
前8个浮点参数：v0-v7 (s0-s7, d0-d7)
超过8个：      通过栈传递 (按声明顺序压栈)
返回值：       x0 (整数), v0 (浮点)
大型结构体：   通过x8传递结果地址
```

### 栈帧结构

```text
高地址
+------------------+
| 第n个参数        |  <- 超过x0-x7的参数
| ...              |
| 第9个参数        |
+------------------+
| 返回地址 (LR)    |  <- 函数调用时保存
| 老的帧指针(x29)  |  <- 可选但推荐
| 局部变量         |
| 保存的寄存器     |  <- x19-x28需要保存
+------------------+  <- SP (当前栈指针，16字节对齐)
低地址
```

### 函数调用流程

```assembly
// 调用者 (Caller)
stp x29, x30, [sp, #-16]!   // 保存帧指针和返回地址
mov x29, sp                 // 设置新的帧指针
stp x19, x20, [sp, #-16]!   // 保存其他需要的寄存器
mov x0, #arg1               // 设置参数1
mov x1, #arg2               // 设置参数2
bl function                 // 调用函数
// x0 包含返回值
ldp x19, x20, [sp], #16     // 恢复寄存器
ldp x29, x30, [sp], #16     // 恢复帧指针和返回地址
ret                         // 返回

// 被调用者 (Callee)
function:
stp x29, x30, [sp, #-16]!   // 保存帧指针和返回地址
mov x29, sp                 // 设置帧指针
stp x19, x20, [sp, #-16]!   // 保存需要使用的寄存器
// 函数体
mov x0, #return_val         // 设置返回值
ldp x19, x20, [sp], #16     // 恢复寄存器
ldp x29, x30, [sp], #16     // 恢复帧指针和返回地址
ret                         // 返回
```

## 指令集合

> AArch32 和 AArch64 指令字长都是 4 字节。

### 指令格式

一般格式如下：

```assembly
MNEMONIC{条件} {目的寄存器}, 操作符1, 操作符2
助记符{条件执行} {目的寄存器}, 操作符1, 操作符2
```

由于AArch64指令的灵活性，不是全部的指令都满足这个模板，不过大部分都满足了。下面来说说模板中的含义:

```assembly
MNEMONIC     - 指令的助记符如ADD
{条件}       - 可选的条件执行后缀
{目的寄存器} - 存储结果的目的寄存器
操作符1      - 第一个操作数，寄存器或者是一个立即数
操作符2      - 第二个(可变的)操作数，可以是一个立即数或者寄存器或者有偏移量的寄存器
```

### 条件执行

AArch64通过条件分支指令实现条件执行：

| 条件码 | 助记符 | 含义 | NZCV标志位条件 |
|--------|--------|------|----------------|
| 0000 | EQ | 相等 | Z = 1 |
| 0001 | NE | 不相等 | Z = 0 |
| 0010 | CS/HS | 进位/无符号大于等于 | C = 1 |
| 0011 | CC/LO | 无进位/无符号小于 | C = 0 |
| 0100 | MI | 负数 | N = 1 |
| 0101 | PL | 正数或零 | N = 0 |
| 0110 | VS | 溢出 | V = 1 |
| 0111 | VC | 无溢出 | V = 0 |
| 1000 | HI | 无符号大于 | C=1且Z=0 |
| 1001 | LS | 无符号小于等于 | C=0或Z=1 |
| 1010 | GE | 有符号大于等于 | N = V |
| 1011 | LT | 有符号小于 | N ≠ V |
| 1100 | GT | 有符号大于 | Z=0且N=V |
| 1101 | LE | 有符号小于等于 | Z=1或N≠V |
| 1110 | AL | 总是执行 | 任何 |
| 1111 | NV | 从不执行 | 无 |

示例：

```assembly
cmp x0, #5         // 比较x0和5
b.gt greater       // 如果x0 > 5，跳转到greater
b.le less_equal    // 如果x0 <= 5，跳转到less_equal
csel x1, x2, x3, gt // 如果条件为真选择x2，否则选择x3
```

### 操作数类型

第二操作数是一个可变操作数，可以以各种形式使用：

```assembly
#123                    // 立即数
Xn                      // 64位寄存器
Wn                      // 32位寄存器
Xn, LSL #n              // 对寄存器中的值进行逻辑左移n位后的值
Xn, LSR #n              // 对寄存器中的值进行逻辑右移n位后的值
Xn, ASR #n              // 对寄存器中的值进行算术右移n位后的值
Xn, ROR #n              // 对寄存器中的值进行循环右移n位后的值
```

基本示例：

```assembly
ADD   x0, x1, x2         // 将第一操作数x1的内容与第二操作数x2的内容相加，将结果存储到x0中
ADD   x0, x1, #2         // 将第一操作数x1的内容与第二操作数一个立即数相加，将结果存到x0中
MOV   x0, #5             // 将立即数5移动到x0中
MOV   x0, x1, LSL #1     // 将第一操作数x1寄存器中的值逻辑左移1位后存入x0
```

### 指令分类

AArch64指令可以分为以下几类：

#### 数据处理指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| MOV | 移动数据 | `mov x0, x1` | 将x1的值复制到x0 |
| MVN | 取反码移动数据 | `mvn x0, x1` | 将x1按位取反后移动到x0 |
| ADD | 数据相加 | `add x0, x1, x2` | x0 = x1 + x2 |
| SUB | 数据相减 | `sub x0, x1, x2` | x0 = x1 - x2 |
| MUL | 数据相乘 | `mul x0, x1, x2` | x0 = x1 * x2 |
| UDIV | 无符号除法 | `udiv x0, x1, x2` | x0 = x1 / x2 (无符号) |
| SDIV | 有符号除法 | `sdiv x0, x1, x2` | x0 = x1 / x2 (有符号) |
| AND | 比特位与 | `and x0, x1, x2` | x0 = x1 & x2 |
| ORR | 比特位或 | `orr x0, x1, x2` | x0 = x1 \| x2 |
| EOR | 比特位异或 | `eor x0, x1, x2` | x0 = x1 ^ x2 |
| BIC | 位清除 | `bic x0, x1, x2` | x0 = x1 & (~x2) |
| CMP | 比较操作 | `cmp x0, x1` | 比较x0和x1，设置标志位 |
| CMN | 负数比较 | `cmn x0, x1` | 比较x0和-x1，设置标志位 |
| TST | 测试 | `tst x0, x1` | 执行x0 & x1，仅设置标志位 |

#### 移位操作指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| LSL | 逻辑左移 | `lsl x0, x1, #2` | 将x1左移2位后存入x0 |
| LSR | 逻辑右移 | `lsr x0, x1, #2` | 将x1逻辑右移2位后存入x0 |
| ASR | 算术右移 | `asr x0, x1, #2` | 将x1算术右移2位后存入x0 |
| ROR | 循环右移 | `ror x0, x1, #2` | 将x1循环右移2位后存入x0 |

#### 分支和跳转指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| B | 分支跳转 | `b label` | 无条件跳转到标签 |
| BL | 链接分支跳转 | `bl function` | 跳转并保存返回地址到x30 |
| BR | 分支跳转寄存器 | `br x0` | 跳转到x0地址 |
| BLR | 链接分支跳转寄存器 | `blr x0` | 跳转到x0地址并保存返回地址 |
| RET | 返回 | `ret` | 从x30返回 |
| CBZ | 零分支 | `cbz x0, label` | 如果x0为0则跳转 |
| CBNZ | 非零分支 | `cbnz x0, label` | 如果x0不为0则跳转 |
| TBZ | 测试位零分支 | `tbz x0, #1, label` | 如果x0的第1位为0则跳转 |
| TBNZ | 测试位非零分支 | `tbnz x0, #1, label` | 如果x0的第1位为1则跳转 |

#### 加载/存储指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| LDR | 加载寄存器 | `ldr x0, [x1]` | 从x1地址加载64位数据到x0 |
| LDRB | 加载字节 | `ldrb w0, [x1]` | 从x1地址加载8位数据到w0 |
| LDRH | 加载半字 | `ldrh w0, [x1]` | 从x1地址加载16位数据到w0 |
| LDRSB | 加载有符号字节 | `ldrsb x0, [x1]` | 加载8位有符号数据并扩展 |
| LDRSH | 加载有符号半字 | `ldrsh x0, [x1]` | 加载16位有符号数据并扩展 |
| LDRSW | 加载有符号字 | `ldrsw x0, [x1]` | 加载32位有符号数据并扩展 |
| STR | 存储寄存器 | `str x0, [x1]` | 将x0的64位数据存储到x1地址 |
| STRB | 存储字节 | `strb w0, [x1]` | 将w0的低8位存储到x1地址 |
| STRH | 存储半字 | `strh w0, [x1]` | 将w0的低16位存储到x1地址 |

#### 多寄存器加载/存储指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| LDP | 加载寄存器对 | `ldp x0, x1, [x2]` | 从x2地址加载两个64位数据 |
| STP | 存储寄存器对 | `stp x0, x1, [x2]` | 将两个64位数据存储到x2地址 |
| LDM | 多次加载 | `ldm x0, {x1-x3}` | 从x0地址加载多个寄存器 |
| STM | 多次存储 | `stm x0, {x1-x3}` | 将多个寄存器存储到x0地址 |

#### 特殊指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| MRS | 系统寄存器读取 | `mrs x0, nzcv` | 将NZCV内容复制到x0 |
| MSR | 系统寄存器写入 | `msr nzcv, x0` | 将x0内容复制到NZCV |
| SVC | 系统调用 | `svc #0` | 触发系统调用中断 |
| NOP | 空操作 | `nop` | 不执行任何操作 |
| WFI | 等待中断 | `wfi` | 进入低功耗模式等待中断 |
| DMB | 数据内存屏障 | `dmb sy` | 数据内存屏障 |
| DSB | 数据同步屏障 | `dsb sy` | 数据同步屏障 |
| ISB | 指令同步屏障 | `isb` | 指令同步屏障 |

### 重点指令详解

#### 算术运算指令

| 指令 | 计算公式 | 示例 | 备注 |
|------|----------|------|------|
| ADD Xd, Xn, Xm | Xd = Xn + Xm | `add x0, x1, x2` | 加法运算 |
| ADD Xd, Xn, #imm | Xd = Xn + #imm | `add x0, x1, #5` | 立即数加法 |
| SUB Xd, Xn, Xm | Xd = Xn - Xm | `sub x0, x1, x2` | 减法 |
| SUB Xd, Xn, #imm | Xd = Xn - #imm | `sub x0, x1, #5` | 立即数减法 |
| MUL Xd, Xn, Xm | Xd = Xn * Xm | `mul x0, x1, x2` | 64位乘法 |
| MADD Xd, Xn, Xm, Xa | Xd = Xa + (Xn * Xm) | `madd x0, x1, x2, x3` | 乘加运算 |
| MSUB Xd, Xn, Xm, Xa | Xd = Xa - (Xn * Xm) | `msub x0, x1, x2, x3` | 乘减运算 |
| SMULL Xd, Wn, Wm | Xd = Wn * Wm | `smull x0, w1, w2` | 有符号乘法扩展 |
| UMULL Xd, Wn, Wm | Xd = Wn * Wm | `umull x0, w1, w2` | 无符号乘法扩展 |
| UDIV Xd, Xn, Xm | Xd = Xn / Xm | `udiv x0, x1, x2` | 无符号除法 |
| SDIV Xd, Xn, Xm | Xd = Xn / Xm | `sdiv x0, x1, x2` | 有符号除法 |

#### 数据传输指令示例

| 指令 | 目的 | 源 | 描述 |
|------|------|----|----- |
| MOV | x0 | x1 | 将 x1 里面的数据复制到 x0 中 |
| MOV | x0 | #0x1234 | 将立即数0x1234加载到x0中 |
| MRS | x0 | nzcv | 将特殊寄存器 NZCV 里面的数据复制到 x0 中 |
| MSR | nzcv | x1 | 将 x1 里面的数据复制到特殊寄存器 NZCV 中 |
| LDR | x0 | =0x1234567890abcdef | 将地址/常量加载到 x0 中 |
| LDR | x0 | [x1] | 从x1指向的地址加载数据到x0 |
| LDR | x0 | [x1, #8] | 从x1+8地址加载数据到x0 |
| LDR | x0 | [x1, x2] | 从x1+x2地址加载数据到x0 |
| LDR | x0 | [x1], #8 | 从x1地址加载数据到x0，然后x1=x1+8 |
| LDR | x0 | [x1, #8]! | x1=x1+8，然后从x1地址加载数据到x0 |
| STR | x1 | [x0] | 将 x1 中的值写入到 x0 中所保存的地址中 |

#### 栈操作指令

| 指令 | 操作数 | 描述 | 等价指令 |
|------|--------|------|----------|
| STP | x0, x1, [sp, #-16]! | 将 x0,x1 压栈并预递减 | `str x0,[sp,#-16]!; str x1,[sp,#8]` |
| LDP | x0, x1, [sp], #16 | 从栈中弹出到 x0,x1 并后递增 | `ldr x0,[sp]; ldr x1,[sp,#8]; add sp,sp,#16` |
| STP | x29, x30, [sp, #-16]! | 保存帧指针和返回地址 | 标准函数序言 |
| LDP | x29, x30, [sp], #16 | 恢复帧指针和返回地址 | 标准函数结尾 |

#### 寻址模式详解

AArch64支持多种灵活的寻址模式：

##### 立即数寻址

```assembly
mov x0, #100        // 将立即数100加载到x0
add x1, x2, #4      // x1 = x2 + 4
```

##### 寄存器寻址

```assembly
mov x0, x1          // 将x1的值复制到x0
add x0, x1, x2      // x0 = x1 + x2
```

##### 寄存器间接寻址

```assembly
ldr x0, [x1]        // 从x1指向的地址加载数据到x0
str x0, [x1]        // 将x0的数据存储到x1指向的地址
```

##### 基址加偏移寻址

```assembly
ldr x0, [x1, #8]    // 从x1+8地址加载数据，x1不变
ldr x0, [x1, x2]    // 从x1+x2地址加载数据，x1不变
ldr x0, [x1, x2, lsl #3]  // 从x1+(x2<<3)地址加载数据
```

##### 前索引寻址（预递增/递减）

```assembly
ldr x0, [x1, #8]!   // x1 = x1 + 8, 然后从x1地址加载数据
ldr x0, [x1, x2]!   // x1 = x1 + x2, 然后从x1地址加载数据
```

##### 后索引寻址（后递增/递减）

```assembly
ldr x0, [x1], #8    // 从x1地址加载数据，然后x1 = x1 + 8
ldr x0, [x1], x2    // 从x1地址加载数据，然后x1 = x1 + x2
```

重要说明：

- `ldr x3, [x1, x2, lsl #3]` - 不会改变寄存器x1的值
- `ldr x3, [x1, x2, lsl #3]!` - 感叹号代表事先更新，会改变x1的值为x1+(x2<<3)
- `ldr x2, [x1], x2, lsl #3` - 事后更新，先加载数据，然后改变x1的值

#### 数据类型支持

AArch64支持多种数据类型的操作：

##### 数据类型表

| 数据类型 | 大小 | 后缀 | 有符号后缀 | 描述 |
|----------|------|------|------------|------|
| 字节 (Byte) | 8位 | B | SB | 无符号/有符号字节 |
| 半字 (Halfword) | 16位 | H | SH | 无符号/有符号半字 |
| 字 (Word) | 32位 | W | SW | 无符号/有符号32位数据 |
| 双字 (Doubleword) | 64位 | X | 无 | 64位数据 |

##### 加载指令示例

```assembly
ldrb  w0, [x1]      // 加载无符号字节，高位清零
ldrsb x0, [x1]      // 加载有符号字节，符号扩展到64位
ldrh  w0, [x1]      // 加载无符号半字，高位清零  
ldrsh x0, [x1]      // 加载有符号半字，符号扩展到64位
ldr   w0, [x1]      // 加载32位字，x0高32位清零
ldrsw x0, [x1]      // 加载有符号32位字，符号扩展到64位
ldr   x0, [x1]      // 加载64位双字
```

##### 存储指令示例

```assembly
strb  w0, [x1]      // 存储w0的低8位
strh  w0, [x1]      // 存储w0的低16位
str   w0, [x1]      // 存储w0的32位
str   x0, [x1]      // 存储x0的64位
```

##### 数据类型范围

| 类型 | 范围 | 用途 |
|------|------|------|
| 无符号字节 | 0 ~ 255 | 字符、小整数 |
| 有符号字节 | -128 ~ 127 | 有符号小整数 |
| 无符号半字 | 0 ~ 65535 | 较大整数、Unicode |
| 有符号半字 | -32768 ~ 32767 | 有符号整数 |
| 无符号字 | 0 ~ 4294967295 | 32位整数、地址 |
| 有符号字 | -2147483648 ~ 2147483647 | 32位有符号整数 |
| 无符号双字 | 0 ~ 18446744073709551615 | 64位整数、地址 |

### 常用编程模式

#### 循环结构

```assembly
// for循环示例: for(int i=0; i<10; i++)
mov x0, #0          // i = 0
loop:
    cmp x0, #10     // 比较 i 和 10
    b.ge loop_end   // 如果 i >= 10 跳出循环
    // 循环体代码
    add x0, x0, #1  // i++
    b loop          // 跳回循环开始
loop_end:

// while循环示例: while(condition)
while_loop:
    // 检查条件的代码
    cmp x0, #0      // 检查条件
    b.eq while_end  // 条件为假则退出
    // 循环体代码
    b while_loop    // 继续循环
while_end:
```

#### 条件判断

```assembly
// if-else 结构
cmp x0, #5          // 比较 x0 和 5
b.lt else_branch    // 如果 x0 < 5 跳到 else
    // if 分支代码
    mov x1, #1
    b endif
else_branch:
    // else 分支代码
    mov x1, #0
endif:

// switch-case 结构
cmp x0, #1
b.eq case1
cmp x0, #2  
b.eq case2
cmp x0, #3
b.eq case3
b default_case

case1:
    // case 1 代码
    b switch_end
case2:
    // case 2 代码  
    b switch_end
case3:
    // case 3 代码
    b switch_end
default_case:
    // 默认情况代码
switch_end:
```

#### 函数调用模板

```assembly
// 标准函数模板
function_name:
    stp x29, x30, [sp, #-16]!   // 保存帧指针和返回地址
    mov x29, sp                 // 设置帧指针
    stp x19, x20, [sp, #-16]!   // 保存其他需要的寄存器
    sub sp, sp, #32             // 为局部变量分配栈空间
    
    // 函数体
    // 参数在 x0-x7 中
    // 局部变量使用栈空间
    
    mov x0, #return_val         // 设置返回值
    add sp, sp, #32             // 释放栈空间
    ldp x19, x20, [sp], #16     // 恢复寄存器
    ldp x29, x30, [sp], #16     // 恢复帧指针和返回地址
    ret                         // 返回

// 调用函数
    mov x0, #arg1       // 第一个参数
    mov x1, #arg2       // 第二个参数  
    mov x2, #arg3       // 第三个参数
    mov x3, #arg4       // 第四个参数
    bl function_name    // 调用函数
    // 返回值在 x0 中
```

#### 数组操作

```assembly
// 数组遍历示例
adr x0, array_base      // 数组基地址
mov x1, #0              // 索引 i = 0
mov x2, #array_size     // 数组大小

array_loop:
    cmp x1, x2          // 比较 i 和 size
    b.ge array_end      // i >= size 则结束
    
    ldr x3, [x0, x1, lsl #3]  // 加载 array[i] (假设64位数组)
    // 处理 x3 中的数据
    
    add x1, x1, #1      // i++
    b array_loop
array_end:

// 字符串长度计算
adr x0, string_ptr      // 字符串指针
mov x1, #0              // 长度计数器

strlen_loop:
    ldrb w2, [x0, x1]   // 加载当前字符
    cbz w2, strlen_end  // 检查是否为'\0'，是则结束
    add x1, x1, #1      // 长度++
    b strlen_loop
strlen_end:
    // x1 包含字符串长度
```

#### 位操作技巧

```assembly
// 检查第n位是否为1
mov x1, #1
lsl x1, x1, x0      // x1 = 1 << n
tst x2, x1          // 测试 x2 的第n位
b.ne bit_is_set     // 如果位为1则跳转

// 设置第n位为1  
mov x1, #1
lsl x1, x1, x0      // x1 = 1 << n
orr x2, x2, x1      // x2 |= (1 << n)

// 清除第n位
mov x1, #1
lsl x1, x1, x0      // x1 = 1 << n
bic x2, x2, x1      // x2 &= ~(1 << n)

// 切换第n位
mov x1, #1
lsl x1, x1, x0      // x1 = 1 << n  
eor x2, x2, x1      // x2 ^= (1 << n)

// 计算2的幂次
mov x1, #1
lsl x1, x1, x0      // x1 = 2^x0

// 除以2的幂次(无符号)
lsr x1, x2, x0      // x1 = x2 / (2^x0)

// 除以2的幂次(有符号)
asr x1, x2, x0      // x1 = x2 / (2^x0) (保持符号)
```

#### 内存对齐和优化

```assembly
// 8字节对齐检查
tst x0, #7          // 检查低3位
b.ne not_aligned    // 如果不为0则未对齐

// 向上对齐到8字节边界
add x0, x0, #7      // x0 += 7
and x0, x0, #~7     // x0 &= ~7

// 向下对齐到8字节边界  
and x0, x0, #~7     // x0 &= ~7

// 快速清零内存块
mov x1, #0          // 清零值
mov x2, x0          // 保存起始地址
add x3, x0, x3      // 计算结束地址
clear_loop:
    cmp x2, x3
    b.ge clear_end
    str x1, [x2], #8  // 存储0并递增地址
    b clear_loop
clear_end:

// 使用SIMD加速内存操作
movi v0.16b, #0     // 设置128位全零向量
clear_simd_loop:
    cmp x2, x3
    b.ge clear_simd_end
    str q0, [x2], #16 // 存储128位0并递增地址
    b clear_simd_loop
clear_simd_end:
```

#### 条件选择指令

```assembly
// 条件选择指令的使用
cmp x0, x1
csel x2, x3, x4, gt  // 如果 x0 > x1，x2 = x3，否则 x2 = x4
csinc x2, x3, x4, eq // 如果相等，x2 = x3，否则 x2 = x4 + 1
csinv x2, x3, x4, ne // 如果不等，x2 = x3，否则 x2 = ~x4
csneg x2, x3, x4, lt // 如果 x0 < x1，x2 = x3，否则 x2 = -x4

// 实现 max(a, b)
cmp x0, x1
csel x2, x0, x1, gt  // x2 = max(x0, x1)

// 实现 min(a, b)  
cmp x0, x1
csel x2, x0, x1, lt  // x2 = min(x0, x1)

// 实现 abs(a)
cmp x0, #0
csneg x1, x0, x0, ge // x1 = (x0 >= 0) ? x0 : -x0
```

这些编程模式涵盖了AArch64汇编中最常用的结构和技巧，可以作为编写AArch64汇编程序的参考模板。AArch64相比ARMv7提供了更加规整的指令集、更大的寄存器、更强的性能和更好的扩展性。
