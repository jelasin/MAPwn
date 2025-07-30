#!/bin/sh

pwndbg -q \
  -ex "target remote :1234" \
  -ex "b *0x106F0" \
  -ex "b *0x10780" \
  -ex "c"
