from pwncli import * # type: ignore

context.binary = './heap'
context.log_level = 'debug'

import argparse

parser = argparse.ArgumentParser(description='Exploit static binary with QEMU')
parser.add_argument('--debug', action='store_true', help='Run in debug mode')
args = parser.parse_args()

debug_flag = False

if args.debug:
    gift.io = process(['qemu-arm', '-E', 'GLIBC_TUNABLES=glibc.malloc.tcache_count=0', '-g', '1234', '-L', './lib','./heap'])
    debug_flag = True
else:
    gift.io = process(['qemu-arm', '-E', 'GLIBC_TUNABLES=glibc.malloc.tcache_count=0', '-L', './lib','./heap'])

gift.elf = ELF('./heap')
gift.libc = ELF('./lib/lib/libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
# CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def debug(gdbscript="", stop=False):
    if isinstance(io, process):
        gdb.attach(io, gdbscript=gdbscript)
        if stop:
            pause()

def cmd(choice: str):
    ru('Enter your choice:\n')
    sl(choice)

def add(idx, size):
    cmd('1')
    ru('Enter index and size:\n')
    sl(f"{idx} {size}\n")
    ru('Memory allocated.\n')

def dele(idx):
    cmd('2')
    ru('Enter index to free:')
    sl(f"{idx}\n")
    ru('Memory freed.\n')

def edit(idx, size, buf):
    cmd('3')
    ru('Enter index and size to edit:\n')
    sl(f"{idx} {size}\n")
    s(buf)
    ru('Memory edited.\n')

def show(idx, size):
    cmd('4')
    ru('Enter index and size to show:\n')
    sl(f"{idx} {size}\n")



ia()
