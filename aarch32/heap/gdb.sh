#!/bin/sh

pwndbg -q \
  -ex "target remote :1234" \
  -ex "b *\$rebase(0x88C)" \
  -ex "b *\$rebase(0x850)" \
  -ex "b *\$rebase(0xB44)" \
  -ex "c"
