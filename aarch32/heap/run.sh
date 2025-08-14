#!/bin/sh

qemu-arm \
    -E GLIBC_TUNABLES=glibc.malloc.tcache_count=0 \
    -L ./lib \
    ./heap