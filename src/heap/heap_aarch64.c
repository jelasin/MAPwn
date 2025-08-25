#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>

char * heap_arr[0x10];

void back_door() 
{
    system("/bin/sh");

    // 使用 volatile 变量来防止编译器优化
    volatile int never_true = 0;
    if(never_true) 
    {
        __asm__ volatile (
            "ldp x0, x1, [sp], #16  \n\t"
            "ldp x2, x3, [sp], #16  \n\t"
            "ldr lr, [sp], #8       \n\t"
            "ret                    \n\t"
            "ldp x8, lr, [sp], #16  \n\t"
            "ret                    \n\t"
            "svc #0                 \n\t"
            "ldp x3, lr, [sp], #16  \n\t"
            "br x3                  \n\t"
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

int heap_alloc(size_t idx, size_t size)
{
    heap_arr[idx] = (char*)malloc(size);
    return 0;
}

int heap_free(size_t idx)
{
    free(heap_arr[idx]);
    return 0;
}

ssize_t heap_edit(size_t idx, size_t size)
{
    ssize_t nbytes = read(STDIN_FILENO, heap_arr[idx], size);
    return nbytes;
}

int heap_show(size_t idx, size_t size)
{
    ssize_t nbytes = write(STDOUT_FILENO, heap_arr[idx], size);
    return nbytes;
}

int main()
{
    puts("==== heap bug input ====");
    while (true)
    {
        puts("1. alloc\n2. free\n3. edit\n4. show\n5. exit");
        puts("Enter your choice:");
        char choice[0x10];
        size_t idx, size;
        ssize_t nbytes = 0;
        int nret = 0;
        nbytes = read(STDIN_FILENO, choice, sizeof(choice));
        if (nbytes > 0) {
            choice[nbytes] = '\x00'; // Null-terminate the string
        }
        if (choice[0] == '1') {
            puts("Enter index and size:");
            nret = scanf("%zu %zu", &idx, &size);
            heap_alloc(idx, size);
            puts("Memory allocated.");
        } else if (choice[0] == '2') {
            puts("Enter index to free:");
            nret = scanf("%zu", &idx);
            heap_free(idx);
            puts("Memory freed.");
        } else if (choice[0] == '3') {
            puts("Enter index and size to edit:");
            nret = scanf("%zu %zu", &idx, &size);
            heap_edit(idx, size);
            puts("Memory edited.");
        } else if (choice[0] == '4') {
            puts("Enter index and size to show:");
            nret = scanf("%zu %zu", &idx, &size);
            heap_show(idx, size);
            puts("Memory shown.");
        } else if (choice[0] == '5') {
            break; // Exit the loop
        } else {
            puts("Invalid choice.");
        }
    }
    
    return 0;
}

