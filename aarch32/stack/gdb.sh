#!/bin/sh

pwndbg -q \
  -ex "target remote :1234" \
  -ex "b *0x000106E8" \
  -ex "b *0x00010618" \
  -ex "c"
