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

def debug(gdbscript="", stop=False):
    if isinstance(io, process):
        gdb.attach(io, gdbscript=gdbscript)
        if stop:
            pause()

def decrypt_fastbin_fd(encrypted_fd, chunk_addr=None, bits=64, key=None):
    """
    解密fd指针
    """
    if key is None:
        if chunk_addr is None:
            raise ValueError("必须提供chunk_addr或key参数")
        key = chunk_addr >> 12
    
    real_fd = encrypted_fd ^ key
    
    if bits == 32:
        return real_fd & 0xffffffff
    else:
        return real_fd & 0xffffffffffffffff

def encrypt_fastbin_fd(real_fd, chunk_addr=None, bits=64, key=None):
    """
    加密fd指针
    """
    if key is None:
        if chunk_addr is None:
            raise ValueError("必须提供chunk_addr或key参数")
        key = chunk_addr >> 12
    
    encrypted_fd = real_fd ^ key
    
    if bits == 32:
        return encrypted_fd & 0xffffffff
    else:
        return encrypted_fd & 0xffffffffffffffff

def cmd(choice: str):
    ru('Enter your choice:\n')
    sl(choice)

def add(idx, size):
    cmd('1')
    ru('Enter index and size:\n')
    s(f"{idx} {size}\n")
    ru('Memory allocated.\n')

def dele(idx):
    cmd('2')
    ru('Enter index to free:')
    s(f"{idx}\n")
    ru('Memory freed.\n')

def edit(idx, size, buf):
    cmd('3')
    ru('Enter index and size to edit:\n')
    s(f"{idx} {size}\n")
    s(buf)
    ru('Memory edited.\n')

def show(idx, size):
    cmd('4')
    ru('Enter index and size to show:\n')
    s(f"{idx} {size}\n")

def unlink_attack():
    pass

if __name__ == "__main__":
    unlink_attack()

