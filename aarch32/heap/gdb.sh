#!/bin/sh

pwndbg -q \
  -ex "target remote :1234" \
  -ex "b *\$rebase(0x85C)" \
  -ex "c"
