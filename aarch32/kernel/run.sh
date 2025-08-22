qemu-system-arm \
    -M virt \
    -m 512M \
    -kernel ./zImage \
    -initrd ./rootfs_arm.cpio \
    -append "console=ttyAMA0 rdinit=/init" \
    -nographic