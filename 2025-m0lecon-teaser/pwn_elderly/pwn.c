#include <linux/bitfield.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>

struct params {
    u32 size;
    u32 idx;
    bool account;
};

static bool done = false;

DEFINE_MUTEX(g_mutex);

static long pwn_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct params p;
    int ret = -EINVAL;
    void *ptr = NULL;

    if (copy_from_user(&p, (void *)arg, sizeof(p)))
        return ret;

    if (!p.size || (p.size > 192))
        return ret;

    mutex_lock(&g_mutex);
    if (!done) {
        ptr = kmalloc(p.size, p.account ? GFP_KERNEL_ACCOUNT : GFP_KERNEL);
        if (!ptr)
            goto err;

        u64 page = (u64)ptr & ~0xfffUL;
        u64 pval = (u64)ptr + (p.idx / 8);
        if ((pval & ~0xfffUL) != page)
            goto err;

        change_bit(p.idx, ptr);

        done = 1;
    }

    ptr = NULL;
    ret = 0;
err:
    if (ptr)
        kfree(ptr);
    mutex_unlock(&g_mutex);
    return ret;
}

static struct file_operations pwn_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = pwn_ioctl
};

static struct miscdevice pwn_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "pwn",
    .fops = &pwn_fops
};

static int __init pwn_init(void) {
    if (misc_register(&pwn_dev)) {
        pr_err("misc_register failed\n");
        return -1;
    }

    return 0;
}

static void __exit pwn_exit(void) {
    misc_deregister(&pwn_dev);
}

module_init(pwn_init);
module_exit(pwn_exit);

MODULE_AUTHOR(":|");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("pwn");
