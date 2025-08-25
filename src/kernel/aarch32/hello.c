#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

struct class *bof_class;
struct cdev cdev;
int bof_major = 256;
char *ptr[40];
struct param {
    size_t len;
    char *buf;
    unsigned long idx;
};

long bof_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    char * stack_buf[0x10];
    struct param p_arg;
    copy_from_user(&p_arg, (void *) arg, sizeof(struct param));
    long retval = 0;
    switch (cmd) {
        case 9:
            copy_to_user(p_arg.buf, ptr[p_arg.idx], p_arg.len);
            printk("copy_to_user: 0x%lx\n", *(long *) ptr[p_arg.idx]);
            break;
        case 8:
            copy_from_user(ptr[p_arg.idx], p_arg.buf, p_arg.len);
            break;
        case 7:
            kfree(ptr[p_arg.idx]);
            printk("free: 0x%p\n", ptr[p_arg.idx]);
            break;
        case 5:
            ptr[p_arg.idx] = kmalloc(p_arg.len, GFP_KERNEL);
            printk("alloc: 0x%p, size: %2lx\n", ptr[p_arg.idx], p_arg.len);
            break;
        case 4:
            copy_from_user(stack_buf, p_arg.buf, p_arg.len);
        default:
            retval = -1;
            break;
    }
    return retval;
}

static const struct file_operations bof_fops = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = bof_ioctl,
};

static int bof_init(void) {
    dev_t devno = MKDEV(bof_major, 0);
    int result;
    if (bof_major)
        result = register_chrdev_region(devno, 1, "bof");
    else {
        result = alloc_chrdev_region(&devno, 0, 1, "bof");
        bof_major = MAJOR(devno);
    }
    printk("bof_major /dev/bof: %d\n", bof_major);
    if (result < 0) return result;
    bof_class = class_create(THIS_MODULE, "bof");
    device_create(bof_class, NULL, devno, NULL, "bof");
    cdev_init(&cdev, &bof_fops);
    cdev.owner = THIS_MODULE;
    cdev_add(&cdev, devno, 1);
    return 0;
}

static void bof_exit(void) {
    cdev_del(&cdev);
    device_destroy(bof_class, MKDEV(bof_major, 0));
    class_destroy(bof_class);
    unregister_chrdev_region(MKDEV(bof_major, 0), 1);
    printk("bof exit success\n");
}

MODULE_AUTHOR("exp");
MODULE_LICENSE("GPL");
module_init(bof_init);
module_exit(bof_exit);
