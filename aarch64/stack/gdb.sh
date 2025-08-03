#!/bin/sh

pwndbg -q \
  -ex "target remote :1234" \
  -ex "b *0x400928" \
  -ex "c"
