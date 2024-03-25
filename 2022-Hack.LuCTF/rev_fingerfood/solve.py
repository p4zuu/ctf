#!/usr/bin/env python3

import subprocess
import string
from pwn import *

flag = ["a"]

alphabet = string.printable

i = 0
while '}' not in flag:
    for c in alphabet:
        flag[i] = c
        printable_flag = ''.join(flag)

        with open("flag", "w") as f:
            f.write(printable_flag)

        r = subprocess.run(["strace", "-o", "output", "./FingerFood", "flag"], capture_output=True, text=True)
        
        with open("output", "r") as f:
            output = f.read()

        if output.count("SIGSEGV") != ((len(flag)+1)*2)+1:
            continue
        else:
            i += 1
            info(printable_flag)
            flag.append("a")
            break
