#!/usr/bin/env python3

from pwn import *
from z3 import *
import hashlib

flag = []

def part_one():
    k = 'rev_insomnihack'
    e = [0x5b, 0x27, 0x2a, 0x0b, 0x5d, 0x2c, 0x32, 0x5c, 0x40, 0x1c, 0x2f, 0x24, 0x25, 0x2b, 0x3b][::-1]
    r = []

    assert(len(k) == len(e))
    for i in range(len(k)):
        r.append(chr(ord(k[i]) ^ e[i]))

    return r

def part_two():
    chars = [BitVec(f'{i}', 8) for i in range(15)]
    s = Solver()

    s.add(chars[0xa] + chars[0] + chars[8] == 0x108)
    s.add(chars[0x5] == chars[0x4] + chars[0xd] - 0x59)
    s.add(chars[0xc] == 0x5f)
    s.add(chars[0xc] - chars[0] == 0x2f)
    s.add(chars[0x4] == chars[0x1] - 0x13)
    s.add(chars[0xe] - chars[0xd] - chars[0x2] == 0xffffffe4)
    s.add(chars[0x8] + chars[0x7] + chars[0] == 0xf8)
    s.add(chars[0] + chars[0x8] - chars[0xb] == 0x30)
    s.add(chars[0x3] - chars[0xe] == 0xfffffffff5)
    s.add(chars[0x6] + chars[0xc] - chars[0x8] == 0x63)
    s.add(chars[0x9] - chars[0x4] == 0xf)
    s.add(chars[0xc] - chars[0] + chars[0x6] == chars[0x1] + 0x26)
    s.add(chars[0x2] == chars[0x9] + 0x36 - chars[0x4])
    s.add(chars[0x2] == chars[0x9] - 0x29)
    s.add(chars[0x5] + 2*chars[0] + chars[0x9] == chars[0xa] + 0xa7)


    assert(s.check() == sat)
    m = s.model()

    return [chr(m[chars[i]].as_long()) for i in range(15)]

def part_three():
    hashes = {
        4: "a948b24c8ba4ae4f14b529b599601fd53a155994",
        0xe: "a048299abe57311eacc14f1f3b4cdbfaf481f688",
        5: "dfbf2d46353217af0a8a9031f974e9e29a4bfc56",
        0xc: "25321fea120a49aca98d9ebc835cc5247b1ffed3",
        0xa: "908da3be8224819759a1397a309fc581fd806a0a",
        3: "728e22de533a58061655153156913c2d85c274d8",
        8: "31c39beef6fa5a85ea07f89cfec704d947fcca48",
        2: "7b52c1a1d67b94c7b4ad50b7227a8e67b66ed9e3",
        0xd: "4a5e95179649555542ce2bc16b8c93ad84928afa",
        6: "c1e2c5e19ad30a96baad6e2bb388923b430ad2cc",
        0xb: "4b3e25f59ed48b0c3330f0c3dbf740681c2c5010",
        1: "e54a31693bcb9bf00ca2a26e0801404d14e68ddd",
        9: "9c1e321a441214916556ad0cafa8953d786cb751",
        0: "06576556d1ad802f247cad11ae748be47b70cd9c",
        7: "b03da51041b519b7c12da6cc968bf1bc26de307c",    
    }

    alphabet = string.printable

    r = []
    for i in range(15):
        for c in alphabet:
            tmp = r.copy()
            tmp.append(c)
            o = hashlib.sha1(str.encode(''.join(tmp)))
            h = o.hexdigest()
            if h == hashes[i]:
                r = tmp
                break

    return r

flag += part_one()
flag += part_two()
flag += part_three()

info(f'flag: {"".join(flag)}')
