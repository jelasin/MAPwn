#!/bin/sh

pwndbg -q \
    -ex "target remote :1234" \
    -ex "b *0x107A4" \
    -ex "b *0x107F4" \
    -ex "b *0x10838" \
    -ex "b *0x10880" \
    -ex "c"