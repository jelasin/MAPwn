# MIPSEL 架构基础知识

## MIPSEL 寄存器详解

### 通用寄存器 ($0-$31)

```text
$0       : 零寄存器 (zero) - 永远为0
$1       : 汇编器临时寄存器 (at)
$2-$3    : 函数返回值 (v0, v1)
$4-$7    : 函数参数 (a0, a1, a2, a3)
$8-$15   : 临时寄存器 (t0-t7)
$16-$23  : 保存寄存器 (s0-s7)
$24-$25  : 临时寄存器 (t8, t9)
$26-$27  : 内核保留 (k0, k1)
$28      : 全局指针 (gp)
$29      : 栈指针 (sp)
$30      : 帧指针 (fp/$s8)
$31      : 返回地址 (ra)
```

### 寄存器别名和用途

```text
寄存器  别名  用途                      调用约定
$0      $zero 硬件零寄存器             N/A
$1      $at   汇编器临时寄存器         N/A
$2      $v0   函数返回值/系统调用号     调用者保存
$3      $v1   函数返回值               调用者保存
$4      $a0   第1个参数               调用者保存
$5      $a1   第2个参数               调用者保存
$6      $a2   第3个参数               调用者保存
$7      $a3   第4个参数               调用者保存
$8      $t0   临时寄存器              调用者保存
$9      $t1   临时寄存器              调用者保存
$10     $t2   临时寄存器              调用者保存
$11     $t3   临时寄存器              调用者保存
$12     $t4   临时寄存器              调用者保存
$13     $t5   临时寄存器              调用者保存
$14     $t6   临时寄存器              调用者保存
$15     $t7   临时寄存器              调用者保存
$16     $s0   保存寄存器              被调用者保存
$17     $s1   保存寄存器              被调用者保存
$18     $s2   保存寄存器              被调用者保存
$19     $s3   保存寄存器              被调用者保存
$20     $s4   保存寄存器              被调用者保存
$21     $s5   保存寄存器              被调用者保存
$22     $s6   保存寄存器              被调用者保存
$23     $s7   保存寄存器              被调用者保存
$24     $t8   临时寄存器              调用者保存
$25     $t9   临时寄存器              调用者保存
$26     $k0   内核保留                N/A
$27     $k1   内核保留                N/A
$28     $gp   全局指针                N/A
$29     $sp   栈指针                  N/A
$30     $fp   帧指针                  被调用者保存
$31     $ra   返回地址                被调用者保存
```

### 特殊寄存器

```text
PC      : 程序计数器
HI      : 乘法/除法结果高位
LO      : 乘法/除法结果低位
```

## 字节序 (Endianness)

MIPSEL 采用小端序 (Little Endian) 字节序：

### 字节序对比

```text
数值: 0x12345678

大端序 (Big Endian - MIPS):
地址:  0x1000  0x1001  0x1002  0x1003
字节:    12      34      56      78

小端序 (Little Endian - MIPSEL):
地址:  0x1000  0x1001  0x1002  0x1003
字节:    78      56      34      12
```

### 字节序影响

```text
加载/存储操作：字节在内存中的排列顺序不同
网络字节序：需要进行字节序转换
多字节数据：半字和字的字节顺序相反
位操作：对字节级别的位操作需要注意字节位置
```

### 字节序转换

```assembly
# 32位字节序转换
# 输入: $a0 包含需要转换的32位值
# 输出: $v0 包含转换后的值
swap_endian32:
    # 提取各个字节
    andi $t0, $a0, 0xFF         # 低字节
    srl $t1, $a0, 8
    andi $t1, $t1, 0xFF         # 第二字节
    srl $t2, $a0, 16
    andi $t2, $t2, 0xFF         # 第三字节
    srl $t3, $a0, 24            # 高字节
    
    # 重新组装
    sll $t0, $t0, 24            # 低字节移到高位
    sll $t1, $t1, 16            # 第二字节移到第三位
    sll $t2, $t2, 8             # 第三字节移到第二位
    # $t3 已经是低字节位置
    
    or $v0, $t0, $t1
    or $v0, $v0, $t2
    or $v0, $v0, $t3
    jr $ra
    nop

# 16位字节序转换
swap_endian16:
    andi $t0, $a0, 0xFF         # 低字节
    srl $t1, $a0, 8
    andi $t1, $t1, 0xFF         # 高字节
    
    sll $t0, $t0, 8             # 低字节移到高位
    or $v0, $t0, $t1            # 组合
    jr $ra
    nop
```

## Linux MIPSEL 系统调用表

### 常用系统调用号

```c
#define __NR_syscall                 0
#define __NR_exit                    1
#define __NR_fork                    2
#define __NR_read                    3
#define __NR_write                   4
#define __NR_open                    5
#define __NR_close                   6
#define __NR_waitpid                 7
#define __NR_creat                   8
#define __NR_link                    9
#define __NR_unlink                 10
#define __NR_execve                 11
#define __NR_chdir                  12
#define __NR_time                   13
#define __NR_mknod                  14
#define __NR_chmod                  15
#define __NR_lchown                 16
#define __NR_lseek                  19
#define __NR_getpid                 20
#define __NR_mount                  21
#define __NR_umount                 22
#define __NR_setuid                 23
#define __NR_getuid                 24
#define __NR_kill                   37
#define __NR_mkdir                  39
#define __NR_rmdir                  40
#define __NR_dup                    41
#define __NR_pipe                   42
#define __NR_brk                    45
#define __NR_ioctl                  54
#define __NR_mmap                   90
#define __NR_munmap                 91
#define __NR_mprotect              125
#define __NR_socket                183
#define __NR_bind                  184
#define __NR_connect               185
#define __NR_listen                186
#define __NR_accept                187
```

### 系统调用约定

[系统调用查询](https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html)

```text
系统调用号：$v0 ($2)
参数1-4：  $a0, $a1, $a2, $a3 ($4-$7)
参数5-6：  栈传递
返回值：    $v0 ($2)
调用指令：  syscall
```

### 系统调用示例

```assembly
# write(1, "Hello", 5)
li $v0, 4       # __NR_write
li $a0, 1       # fd = 1 (stdout)
la $a1, hello   # buf = "Hello"
li $a2, 5       # count = 5
syscall         # 系统调用

# exit(0)
li $v0, 1       # __NR_exit
li $a0, 0       # status = 0
syscall
```

## 函数调用约定

### 参数传递

```text
前4个参数：$a0, $a1, $a2, $a3 ($4-$7)
超过4个：  通过栈传递 (小端序存储)
返回值：   $v0, $v1 ($2, $3)
```

### 栈帧结构

```text
高地址
+------------------+
| 第n个参数        |  <- 超过$a0-$a3的参数 (小端序)
| ...              |
| 第5个参数        |
+------------------+
| 返回地址 ($ra)   |  <- 函数调用时保存 (小端序)
| 老的帧指针($fp)  |  <- 可选 (小端序)
| 保存的寄存器     |  <- $s0-$s7需要保存 (小端序)
| 局部变量         |  <- 小端序存储
+------------------+  <- $sp (当前栈指针)
低地址
```

### 函数调用流程

```assembly
# 调用者 (Caller)
# 保存临时寄存器 (如果需要)
sw $t0, -4($sp)
sw $t1, -8($sp)
addiu $sp, $sp, -8

li $a0, arg1        # 设置参数1
li $a1, arg2        # 设置参数2
jal function        # 调用函数
nop                 # 延迟槽

# $v0 包含返回值
addiu $sp, $sp, 8   # 恢复栈
lw $t1, -8($sp)
lw $t0, -4($sp)

# 被调用者 (Callee)
function:
addiu $sp, $sp, -32 # 分配栈空间
sw $ra, 28($sp)     # 保存返回地址
sw $fp, 24($sp)     # 保存帧指针
sw $s0, 20($sp)     # 保存需要使用的寄存器
move $fp, $sp       # 设置新的帧指针

# 函数体

li $v0, return_val  # 设置返回值
lw $s0, 20($sp)     # 恢复寄存器
lw $fp, 24($sp)     # 恢复帧指针
lw $ra, 28($sp)     # 恢复返回地址
addiu $sp, $sp, 32  # 释放栈空间
jr $ra              # 返回
nop                 # 延迟槽
```

## 指令集合

> MIPSEL 指令字长为 4 字节，采用小端序存储。

### 指令格式

MIPSEL 指令分为三种格式（在内存中以小端序存储）：

#### R-Type (寄存器类型)

```text
31    26 25   21 20   16 15   11 10    6 5     0
+--------+-------+-------+-------+-------+-------+
|   op   |  rs   |  rt   |  rd   | shamt | funct |
+--------+-------+-------+-------+-------+-------+
  6 bits  5 bits  5 bits  5 bits  5 bits  6 bits
```

#### I-Type (立即数类型)

```text
31    26 25   21 20   16 15                    0
+--------+-------+-------+------------------------+
|   op   |  rs   |  rt   |      immediate         |
+--------+-------+-------+------------------------+
  6 bits  5 bits  5 bits       16 bits
```

#### J-Type (跳转类型)

```text
31    26 25                                     0
+--------+-----------------------------------------+
|   op   |              address                  |
+--------+-----------------------------------------+
  6 bits              26 bits
```

### 指令分类

#### 算术运算指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| add | add rd, rs, rt | rd = rs + rt | `add $t0, $t1, $t2` | 有符号加法 |
| addu | addu rd, rs, rt | rd = rs + rt | `addu $t0, $t1, $t2` | 无符号加法 |
| addi | addi rt, rs, imm | rt = rs + imm | `addi $t0, $t1, 100` | 立即数加法 |
| addiu | addiu rt, rs, imm | rt = rs + imm | `addiu $t0, $t1, 100` | 无符号立即数加法 |
| sub | sub rd, rs, rt | rd = rs - rt | `sub $t0, $t1, $t2` | 有符号减法 |
| subu | subu rd, rs, rt | rd = rs - rt | `subu $t0, $t1, $t2` | 无符号减法 |
| mult | mult rs, rt | HI:LO = rs * rt | `mult $t0, $t1` | 有符号乘法 |
| multu | multu rs, rt | HI:LO = rs * rt | `multu $t0, $t1` | 无符号乘法 |
| div | div rs, rt | LO=rs/rt, HI=rs%rt | `div $t0, $t1` | 有符号除法 |
| divu | divu rs, rt | LO=rs/rt, HI=rs%rt | `divu $t0, $t1` | 无符号除法 |

#### 逻辑运算指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| and | and rd, rs, rt | rd = rs & rt | `and $t0, $t1, $t2` | 按位与 |
| andi | andi rt, rs, imm | rt = rs & imm | `andi $t0, $t1, 0xFF` | 立即数按位与 |
| or | or rd, rs, rt | rd = rs \| rt | `or $t0, $t1, $t2` | 按位或 |
| ori | ori rt, rs, imm | rt = rs \| imm | `ori $t0, $t1, 0xFF` | 立即数按位或 |
| xor | xor rd, rs, rt | rd = rs ^ rt | `xor $t0, $t1, $t2` | 按位异或 |
| xori | xori rt, rs, imm | rt = rs ^ imm | `xori $t0, $t1, 0xFF` | 立即数按位异或 |
| nor | nor rd, rs, rt | rd = ~(rs \| rt) | `nor $t0, $t1, $t2` | 按位或非 |

#### 移位指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| sll | sll rd, rt, shamt | rd = rt << shamt | `sll $t0, $t1, 2` | 逻辑左移 |
| sllv | sllv rd, rt, rs | rd = rt << rs | `sllv $t0, $t1, $t2` | 变量逻辑左移 |
| srl | srl rd, rt, shamt | rd = rt >> shamt | `srl $t0, $t1, 2` | 逻辑右移 |
| srlv | srlv rd, rt, rs | rd = rt >> rs | `srlv $t0, $t1, $t2` | 变量逻辑右移 |
| sra | sra rd, rt, shamt | rd = rt >> shamt | `sra $t0, $t1, 2` | 算术右移 |
| srav | srav rd, rt, rs | rd = rt >> rs | `srav $t0, $t1, $t2` | 变量算术右移 |

#### 数据传输指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| lw | lw rt, offset(rs) | rt = Memory[rs+offset] | `lw $t0, 0($sp)` | 加载字 (小端序) |
| lh | lh rt, offset(rs) | rt = Memory[rs+offset] | `lh $t0, 0($sp)` | 加载半字(有符号,小端序) |
| lhu | lhu rt, offset(rs) | rt = Memory[rs+offset] | `lhu $t0, 0($sp)` | 加载半字(无符号,小端序) |
| lb | lb rt, offset(rs) | rt = Memory[rs+offset] | `lb $t0, 0($sp)` | 加载字节(有符号) |
| lbu | lbu rt, offset(rs) | rt = Memory[rs+offset] | `lbu $t0, 0($sp)` | 加载字节(无符号) |
| sw | sw rt, offset(rs) | Memory[rs+offset] = rt | `sw $t0, 0($sp)` | 存储字 (小端序) |
| sh | sh rt, offset(rs) | Memory[rs+offset] = rt | `sh $t0, 0($sp)` | 存储半字 (小端序) |
| sb | sb rt, offset(rs) | Memory[rs+offset] = rt | `sb $t0, 0($sp)` | 存储字节 |

#### 立即数加载指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| lui | lui rt, imm | rt = imm << 16 | `lui $t0, 0x1234` | 加载立即数到高位 |
| li | li rt, imm | rt = imm | `li $t0, 100` | 加载立即数(伪指令) |
| la | la rt, label | rt = &label | `la $t0, string` | 加载地址(伪指令) |

#### 比较指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| slt | slt rd, rs, rt | rd = (rs < rt) ? 1 : 0 | `slt $t0, $t1, $t2` | 有符号小于设置 |
| sltu | sltu rd, rs, rt | rd = (rs < rt) ? 1 : 0 | `sltu $t0, $t1, $t2` | 无符号小于设置 |
| slti | slti rt, rs, imm | rt = (rs < imm) ? 1 : 0 | `slti $t0, $t1, 100` | 立即数有符号小于设置 |
| sltiu | sltiu rt, rs, imm | rt = (rs < imm) ? 1 : 0 | `sltiu $t0, $t1, 100` | 立即数无符号小于设置 |

#### 分支跳转指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| beq | beq rs, rt, label | if (rs == rt) PC = label | `beq $t0, $t1, loop` | 相等则分支 |
| bne | bne rs, rt, label | if (rs != rt) PC = label | `bne $t0, $t1, end` | 不相等则分支 |
| bgtz | bgtz rs, label | if (rs > 0) PC = label | `bgtz $t0, positive` | 大于0则分支 |
| blez | blez rs, label | if (rs <= 0) PC = label | `blez $t0, nonpos` | 小于等于0则分支 |
| bltz | bltz rs, label | if (rs < 0) PC = label | `bltz $t0, negative` | 小于0则分支 |
| bgez | bgez rs, label | if (rs >= 0) PC = label | `bgez $t0, nonneg` | 大于等于0则分支 |
| j | j target | PC = target | `j main` | 无条件跳转 |
| jal | jal target | $ra = PC+4; PC = target | `jal function` | 跳转并链接 |
| jr | jr rs | PC = rs | `jr $ra` | 寄存器跳转 |
| jalr | jalr rd, rs | rd = PC+4; PC = rs | `jalr $ra, $t0` | 寄存器跳转并链接 |

#### 特殊指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| nop | nop | 空操作 | `nop` | 无操作(sll $0,$0,0) |
| move | move rd, rs | rd = rs | `move $t0, $t1` | 数据移动(伪指令) |
| mfhi | mfhi rd | rd = HI | `mfhi $t0` | 从HI寄存器移动 |
| mflo | mflo rd | rd = LO | `mflo $t0` | 从LO寄存器移动 |
| mthi | mthi rs | HI = rs | `mthi $t0` | 移动到HI寄存器 |
| mtlo | mtlo rs | LO = rs | `mtlo $t0` | 移动到LO寄存器 |
| syscall | syscall | 系统调用 | `syscall` | 触发系统调用 |
| break | break | 断点异常 | `break` | 触发断点异常 |

### 寻址模式详解

#### 立即数寻址

```assembly
li $t0, 100         # 将立即数100加载到$t0
addi $t1, $t0, 5    # $t1 = $t0 + 5
```

#### 寄存器寻址

```assembly
move $t0, $t1       # 将$t1的值复制到$t0
add $t0, $t1, $t2   # $t0 = $t1 + $t2
```

#### 基址加偏移寻址

```assembly
lw $t0, 0($sp)      # 从$sp+0地址加载数据到$t0 (小端序)
lw $t0, 4($sp)      # 从$sp+4地址加载数据到$t0 (小端序)
sw $t0, 8($sp)      # 将$t0的数据存储到$sp+8地址 (小端序)
```

#### PC相对寻址(分支指令)

```assembly
beq $t0, $t1, label # 如果$t0==$t1则跳转到label
bne $t0, $zero, loop # 如果$t0!=0则跳转到loop
```

#### 绝对寻址(跳转指令)

```assembly
j main              # 无条件跳转到main标签
jal function        # 跳转到function并保存返回地址
```

### 数据类型支持

MIPSEL支持多种数据类型的操作，全部采用小端序存储：

#### 数据类型表

| 数据类型 | 大小 | 后缀 | 有符号后缀 | 描述 | 字节序 |
|----------|------|------|------------|------|--------|
| 字节 (Byte) | 8位 | b | b | 有符号/无符号字节 | N/A |
| 半字 (Halfword) | 16位 | h | h/hu | 有符号/无符号半字 | 小端序 |
| 字 (Word) | 32位 | w | 无 | 32位数据 | 小端序 |

#### 小端序存储示例

```assembly
# 存储0x12345678到地址0x1000
li $t0, 0x12345678
sw $t0, 0x1000($zero)

# 内存布局 (小端序):
# 地址 0x1000: 0x78  (最低字节)
# 地址 0x1001: 0x56
# 地址 0x1002: 0x34  
# 地址 0x1003: 0x12  (最高字节)

# 加载操作
lw $t1, 0x1000($zero)   # $t1 = 0x12345678
lh $t2, 0x1000($zero)   # $t2 = 0x5678 (符号扩展为0x00005678)
lhu $t3, 0x1000($zero)  # $t3 = 0x5678 (零扩展为0x00005678)
lb $t4, 0x1000($zero)   # $t4 = 0x78 (符号扩展为0x00000078)
lbu $t5, 0x1000($zero)  # $t5 = 0x78 (零扩展为0x00000078)
```

#### 加载指令示例

```assembly
lb  $t0, 0($sp)     # 加载有符号字节，符号扩展到32位
lbu $t0, 0($sp)     # 加载无符号字节，高24位清零
lh  $t0, 0($sp)     # 加载有符号半字，符号扩展到32位 (小端序)
lhu $t0, 0($sp)     # 加载无符号半字，高16位清零 (小端序)
lw  $t0, 0($sp)     # 加载32位字 (小端序)
```

#### 存储指令示例

```assembly
sb  $t0, 0($sp)     # 存储$t0的低8位
sh  $t0, 0($sp)     # 存储$t0的低16位 (小端序)
sw  $t0, 0($sp)     # 存储$t0的32位 (小端序)
```

#### 数据类型范围

| 类型 | 范围 | 用途 |
|------|------|------|
| 无符号字节 | 0 ~ 255 | 字符、小整数 |
| 有符号字节 | -128 ~ 127 | 有符号小整数 |
| 无符号半字 | 0 ~ 65535 | 较大整数、Unicode |
| 有符号半字 | -32768 ~ 32767 | 有符号整数 |
| 无符号字 | 0 ~ 4294967295 | 地址、大整数 |

### 常用编程模式

#### 循环结构

```assembly
# for循环示例: for(int i=0; i<10; i++)
li $t0, 0           # i = 0
li $t1, 10          # 循环上限
loop:
    bge $t0, $t1, loop_end  # 如果 i >= 10 跳出循环
    # 循环体代码
    addi $t0, $t0, 1        # i++
    j loop                  # 跳回循环开始
loop_end:

# while循环示例: while(condition)
while_loop:
    # 检查条件的代码
    beq $t0, $zero, while_end   # 条件为假则退出
    # 循环体代码
    j while_loop                # 继续循环
while_end:
```

#### 条件判断

```assembly
# if-else 结构
bne $t0, $t1, else_branch   # 如果 $t0 != $t1 跳到 else
    # if 分支代码
    li $t2, 1
    j endif
else_branch:
    # else 分支代码
    li $t2, 0
endif:

# switch-case 结构  
li $t1, 1
beq $t0, $t1, case1
li $t1, 2
beq $t0, $t1, case2
li $t1, 3
beq $t0, $t1, case3
j default_case

case1:
    # case 1 代码
    j switch_end
case2:
    # case 2 代码
    j switch_end
case3:
    # case 3 代码
    j switch_end
default_case:
    # 默认情况代码
switch_end:
```

#### 函数调用模板

```assembly
# 标准函数模板
function_name:
    addiu $sp, $sp, -32     # 分配栈空间
    sw $ra, 28($sp)         # 保存返回地址 (小端序)
    sw $fp, 24($sp)         # 保存帧指针 (小端序)
    sw $s0, 20($sp)         # 保存需要的寄存器 (小端序)
    sw $s1, 16($sp)         # (小端序)
    move $fp, $sp           # 设置新的帧指针
    
    # 函数体
    # 参数在 $a0-$a3 中
    # 局部变量使用栈空间 (小端序存储)
    
    li $v0, return_val      # 设置返回值
    lw $s1, 16($sp)         # 恢复寄存器 (小端序)
    lw $s0, 20($sp)         # (小端序)
    lw $fp, 24($sp)         # 恢复帧指针 (小端序)
    lw $ra, 28($sp)         # 恢复返回地址 (小端序)
    addiu $sp, $sp, 32      # 释放栈空间
    jr $ra                  # 返回
    nop                     # 延迟槽

# 调用函数
    li $a0, arg1            # 第一个参数
    li $a1, arg2            # 第二个参数
    li $a2, arg3            # 第三个参数
    li $a3, arg4            # 第四个参数
    jal function_name       # 调用函数
    nop                     # 延迟槽
    # 返回值在 $v0 中
```

#### 数组操作

```assembly
# 数组遍历示例 (小端序数组)
la $t0, array           # 数组基地址
li $t1, 0               # 索引 i = 0
li $t2, array_size      # 数组大小

array_loop:
    bge $t1, $t2, array_end     # i >= size 则结束
    
    sll $t3, $t1, 2             # t3 = i * 4 (假设int数组)
    add $t3, $t0, $t3           # t3 = &array[i]
    lw $t4, 0($t3)              # 加载 array[i] (小端序)
    # 处理 $t4 中的数据
    
    addi $t1, $t1, 1            # i++
    j array_loop
array_end:

# 字符串长度计算
la $t0, string          # 字符串指针
li $t1, 0               # 长度计数器

strlen_loop:
    add $t2, $t0, $t1   # 计算当前字符地址
    lbu $t3, 0($t2)     # 加载当前字符
    beq $t3, $zero, strlen_end  # 检查是否为'\0'
    addi $t1, $t1, 1    # 长度++
    j strlen_loop
strlen_end:
    # $t1 包含字符串长度
```

#### 位操作技巧

```assembly
# 检查第n位是否为1
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 1 << n
and $t2, $t3, $t1       # 测试 $t3 的第n位
bne $t2, $zero, bit_is_set

# 设置第n位为1
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 1 << n
or $t2, $t2, $t1        # $t2 |= (1 << n)

# 清除第n位
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 1 << n
nor $t1, $t1, $zero     # $t1 = ~(1 << n)
and $t2, $t2, $t1       # $t2 &= ~(1 << n)

# 切换第n位
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 1 << n
xor $t2, $t2, $t1       # $t2 ^= (1 << n)

# 计算2的幂次
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 2^$t0

# 除以2的幂次(无符号)
srlv $t1, $t2, $t0      # $t1 = $t2 / (2^$t0)

# 除以2的幂次(有符号)
srav $t1, $t2, $t0      # $t1 = $t2 / (2^$t0) (保持符号)
```

#### 内存对齐和优化

```assembly
# 4字节对齐检查
andi $t1, $t0, 3        # 检查低2位
bne $t1, $zero, not_aligned

# 向上对齐到4字节边界
addi $t0, $t0, 3        # $t0 += 3
andi $t0, $t0, 0xFFFFFFFC   # $t0 &= ~3

# 向下对齐到4字节边界
andi $t0, $t0, 0xFFFFFFFC   # $t0 &= ~3

# 快速清零内存块 (小端序)
move $t1, $zero         # 清零值
move $t2, $t0           # 保存起始地址
add $t3, $t0, $t4       # 计算结束地址
clear_loop:
    bge $t2, $t3, clear_end
    sw $t1, 0($t2)      # 存储0 (小端序)
    addi $t2, $t2, 4    # 递增地址
    j clear_loop
clear_end:
```

#### 字节序相关操作

```assembly
# 读取大端序数据并转换为小端序
read_big_endian:
    lbu $t0, 0($a0)     # 读取第0字节 (最高字节)
    lbu $t1, 1($a0)     # 读取第1字节
    lbu $t2, 2($a0)     # 读取第2字节  
    lbu $t3, 3($a0)     # 读取第3字节 (最低字节)
    
    sll $t0, $t0, 24    # 最高字节移到正确位置
    sll $t1, $t1, 16    # 第二字节移到正确位置
    sll $t2, $t2, 8     # 第三字节移到正确位置
    # $t3 已经在正确位置
    
    or $v0, $t0, $t1    # 组合结果
    or $v0, $v0, $t2
    or $v0, $v0, $t3
    jr $ra
    nop

# 将小端序数据写入为大端序
write_big_endian:
    andi $t0, $a1, 0xFF         # 提取最低字节
    srl $t1, $a1, 8
    andi $t1, $t1, 0xFF         # 提取第二字节
    srl $t2, $a1, 16
    andi $t2, $t2, 0xFF         # 提取第三字节
    srl $t3, $a1, 24            # 提取最高字节
    
    sb $t3, 0($a0)      # 存储最高字节到第0位置
    sb $t2, 1($a0)      # 存储第三字节到第1位置
    sb $t1, 2($a0)      # 存储第二字节到第2位置
    sb $t0, 3($a0)      # 存储最低字节到第3位置
    jr $ra
    nop
```

### 延迟槽 (Delay Slot)

MIPSEL架构同样具有分支延迟槽特性：

```assembly
# 分支指令后的一条指令总是会被执行
beq $t0, $t1, target
add $t2, $t3, $t4       # 延迟槽：无论分支是否发生都会执行

# 跳转指令也有延迟槽
jal function
move $a0, $t0           # 延迟槽：设置参数

# 如果延迟槽没有有用的指令，使用nop
j loop
nop                     # 延迟槽：空操作
```

### MIPSEL 特定注意事项

#### 字节序转换场景

```text
1. 网络编程：网络字节序为大端序，需要转换
2. 文件格式：某些文件格式使用大端序
3. 跨平台数据交换：与大端序系统交换数据
4. 协议实现：某些协议规定使用大端序
5. 硬件接口：某些硬件设备使用大端序
```

#### 调试技巧

```assembly
# 打印32位数的各个字节 (调试用)
print_bytes:
    move $t0, $a0           # 保存原值
    
    # 打印最低字节
    andi $a0, $t0, 0xFF
    li $v0, 1               # print_int系统调用
    syscall
    
    # 打印第二字节
    srl $t1, $t0, 8
    andi $a0, $t1, 0xFF
    syscall
    
    # 打印第三字节
    srl $t1, $t0, 16
    andi $a0, $t1, 0xFF
    syscall
    
    # 打印最高字节
    srl $a0, $t0, 24
    syscall
    
    jr $ra
    nop
```

这些编程模式涵盖了MIPSEL汇编中最常用的结构和技巧，特别强调了小端序字节序的处理，可以作为编写MIPSEL汇编程序的参考模板。
