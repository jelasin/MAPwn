#!/bin/sh

pwndbg -q \
    -ex "target remote :1234" \
    -ex "b *\$rebase(0xAE8)" \
    -ex "b *\$rebase(0xB78)" \
    -ex "b *\$rebase(0xBFC)" \
    -ex "b *\$rebase(0xC84)" \
    -ex "c"