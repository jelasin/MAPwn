#!/bin/sh

gdb-multiarch -q \
  -ex "set architecture riscv:rv32" \
  -ex "target remote :1234" \
  -ex "b *0x109D0" \
  -ex "c"
