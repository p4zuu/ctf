#/usr/bin/env python3

from pwn import *

context.log_level = logging.DEBUG

HOST = 'chal.tuctf.com'
PORT = 30002

r = remote(HOST, PORT)

class Lock:
    def __init__(self, val) -> None:
        self.init_state = val
        self.current_state = self.init_state

        self.set_init_state()

    def inc(self):
        self.current_state += 1

    def set_init_state(self):
        s_state = str(self.init_state).rjust(4, '0')
        
        for w in range(4):
            for _ in range(int(s_state[w])):
                l = r.sendlineafter('to exit', b'1')
                info(l)
                if b'TUCTF' in l:    
                        exit(0)

                r.sendlineafter('1-4', str((w+1)).encode())
                r.sendlineafter('+/-)', b'+')
    
    def brute(self):
        while self.current_state < 10000:
            prev_state = str(self.current_state).rjust(4, '0')
            self.inc()

            for i in range(4)[::-1]:
                if prev_state[i] != str(self.current_state).rjust(4, '0')[i]:
                    l = r.sendlineafter('to exit', b'1')
                    info(l)
                    if b'TUCTF' in l:    
                        exit(0)

                    r.sendlineafter('1-4', str((i+1)).encode())
                    r.sendlineafter('+/-)', b'+')
            info(f'current code: {self.current_state}')

c = Lock(0)
c.brute()

r.recvall()

