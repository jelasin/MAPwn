#!/bin/sh

pwndbg -q \
  -ex "target remote :1234" \
  -ex "b *0x10000724" \
  -ex "b *0x10000744" \
  -ex "c"
