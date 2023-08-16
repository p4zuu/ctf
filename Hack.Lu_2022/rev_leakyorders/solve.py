#!/usr/bin/env python3

import subprocess
from ctypes import *
import pty
import os

c = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

master, slave = pty.openpty()

p = subprocess.Popen(['/chal/sigs'], stdout=slave)
stdout = os.fdopen(os.dup(master), 'rb', 0)


for _ in range(0xf):
    numbers = list(map(int, stdout.readline().strip().split(b' ')))
    print(numbers)
    for n in numbers:
        c.sigqueue(p.pid, n, n)

while True:
    print(stdout.readline())