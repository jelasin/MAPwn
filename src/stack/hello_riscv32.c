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
            "lw a0, 0(sp)           \n\t"
            "lw a1, 4(sp)           \n\t"
            "addi sp, sp, 8         \n\t"
            "lw a2, 0(sp)           \n\t"
            "lw ra, 4(sp)           \n\t"
            "addi sp, sp, 8         \n\t"
            "jr ra                  \n\t"
            "lw a7, 0(sp)           \n\t"
            "lw ra, 4(sp)           \n\t"
            "addi sp, sp, 8         \n\t"
            "jr ra                  \n\t"
            "ecall                  \n\t"
            "lw t0, 0(sp)           \n\t"
            "lw ra, 4(sp)           \n\t"
            "addi sp, sp, 8         \n\t"
            "jr t0                  \n\t"
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