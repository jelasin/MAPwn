#!/bin/sh

pwndbg -q \
    -ex "target remote :1234" \
    -ex "b *0x4008C0" \
    -ex "b *0x40093C" \
    -ex "c"