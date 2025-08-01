#!/bin/sh

pwndbg -q \
  -ex "target remote :1234" \
  -ex "b *0x4009F8" \
  -ex "b *0x400A74" \
  -ex "b *0x400A8C" \
  -ex "c"
