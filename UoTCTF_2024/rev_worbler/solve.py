from itertools import chain, product

def worble(s):
    s1 = 5
    s2 = 31

    for n in range(len(s)):
        s1 = (s1 + ord(s[n]) + 7) % 65521
        s2 = (s1 * s2) % 65521

    return (s2 << 16) | s1

def shmorble(s):
    r = ''
    for i in range(len(s)):
        r += s[i - len(s)]
    return r

def blorble(a, b):
    return format(a, 'x') + format(b, 'x')


def bruteforce(charset, maxlength):
    return (''.join(candidate)
        for candidate in chain.from_iterable(product(charset, repeat=i)
        for i in range(maxlength, maxlength + 1)))

target = 'a81c0750d48f0750'

for s in bruteforce('w0rbd13', 9):
    flag ='uoftctf{' + s + '}'
    a = worble(flag)
    b = worble(flag[::-1])
    computed_flag = shmorble(blorble(a, b))
    if computed_flag == target:
        print(flag)
        break
 