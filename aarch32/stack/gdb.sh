#!/bin/sh

pwndbg -q \
    -ex "target remote :1234" \
    -ex "b *0x10668" \
    -ex "b *0x106F8" \
    -ex "c"