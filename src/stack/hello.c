#include <stdio.h>
#include <unistd.h>

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

int main() 
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