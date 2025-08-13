#!/bin/sh

pwndbg -q \
  -ex "target remote :1234" \
  -ex "b *0x100007E4" \
  -ex "b *0x100005D8" \
  -ex "b *0x100005F4" \
  -ex "c"
