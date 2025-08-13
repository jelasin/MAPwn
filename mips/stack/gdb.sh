#!/bin/sh

pwndbg -q \
  -ex "target remote :1234" \
  -ex "b *0x4007C8" \
  -ex "c"
