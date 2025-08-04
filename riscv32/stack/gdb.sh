#!/bin/sh

gdb-multiarch -q \
  -ex "set architecture riscv:rv32" \
  -ex "target remote :1234" \
  -ex "b *0x1072C" \
  -ex "b *0x107F8" \
  -ex "c"
