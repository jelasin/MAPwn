#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void back_door() 
{
    system("/bin/sh");

    // 使用 volatile 变量来防止编译器优化
    volatile int never_true = 0;
    if(never_true) 
    {
        __asm__ volatile (
            /* --- gadget 1: save r3,r4,r5,lr; pop; return --- */
            "mflr 0\n\t"
            "stw 3,0(1)\n\t"
            "stw 4,4(1)\n\t"
            "stw 5,8(1)\n\t"
            "stw 0,12(1)\n\t"
            "addi 1,1,16\n\t"
            "blr\n\t"
            /* --- gadget 2: save r0,lr; pop; return --- */
            "mflr 9\n\t"      /* 备份 lr 到 r9 */
            "stw 0,0(1)\n\t"
            "stw 9,4(1)\n\t"
            "addi 1,1,8\n\t"
            "blr\n\t"
            /* --- gadget 3: syscall --- */
            "sc\n\t"
            /* --- gadget 4: save r13,lr; pop; jump r13 --- */
            "mflr 0\n\t"
            "stw 13,0(1)\n\t"
            "stw 0,4(1)\n\t"
            "addi 1,1,8\n\t"
            "mtlr 13\n\t"    /* 跳转到 r13 所指地址 */
            "blr\n\t"
            :
            :
            : "memory"
        );
    }
}

void init_io()
{
    setbuf(stdout, NULL); // Disable buffering for stdout
    setbuf(stderr, NULL); // Disable buffering for stderr
    setbuf(stdin, NULL);  // Disable buffering for stdin
    alarm(0); // Disable any alarms
}

void __attribute__((constructor)) init() 
{
    init_io(); // Call the initialization function before main
}

int get_str(char *buf, size_t len) 
{
    if (len == 0) return 0; // Avoid zero-length reads
    return read(STDIN_FILENO, buf, len);
}

int welcome() 
{
    printf("Hello, Multi-Architecture Pwn!\n");
    char buffer[0x10];
    printf("Enter a string: ");
    int bytes_read = get_str(buffer, 0x100);
    printf("You entered: %.*s\n", bytes_read, buffer);
    if (bytes_read < 0) {
        perror("Error reading input");
        return 1;
    }
    return 0;
}

int main() 
{
    welcome();
    return 0;
}