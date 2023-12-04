#/usr/bin/env python3

from pwn import *
from math import gcd as bltin_gcd

context.log_level = logging.DEBUG

HOST = 'chal.tuctf.com'
PORT = 30009

move = lambda d: r.sendlineafter(b'Action: ', d.encode())
check = lambda: r.sendlineafter(b'Action: ', b'C')

def parse_frame(lines: [str]) -> ():
    U_line = lines[2]
    U = int(U_line.split('@(')[1].split('@@@&')[0].replace(' ',''))
    F_line = lines[13]
    L = int(F_line.split('.@')[1].split('&@')[0].replace(' ',''))
    F = int(F_line.split('&@')[1].split('%@')[0].replace(' ',''))
    R = int(F_line.split('%@')[1].split('@*')[0].replace(' ',''))
    D_line = lines[24]
    D = int(D_line.split(',@@@@')[1].split('%@@@@')[0].replace(' ',''))
    
    return (U, L, F, R, D)

def get_back() -> int:
    # Turn and check Right wall in the same room
    move('R')

    r.recvuntil(b'.@@@@@@@@')
    frame = []
    for _ in range(26):
        frame.append(r.recvline().decode())
    
    B_line = frame[13]
    B = int(B_line.split('%@')[1].split('@*')[0].replace(' ',''))

    # put in the same direction as the beginning
    move('L')

    return B

class Cube:
    def __init__(self):
        self.grid = [[[Room(x, y, z) for x in range(6)] for y in range(6)] for z in range(6)]
        self.direction = 'F'
    
    def play(self):
        # run over the the all rooms, line after line, stage after stage to fill the whole map,
        # then go over the cube again to check coprime rooms

        # j is the index on Y 
        for z in range(6):
            for y in range(6):
                for x in range(6):
                    info(f'x {x} y {y} z {z} direction {self.direction}')
                    r.recvuntil(b'@@@@@@@@')
                    frame = []
                    for _ in range(26):
                        l = r.recvline()
                        if x == 0 and y == 0 and z == 0:
                           info(l)
                        frame.append(l.decode())

                    (U, L, F, R, D) = parse_frame(frame)
                    B = get_back()

                    if self.direction == 'F':
                        self.grid[z][(y+1)%6][x].B = F
                        self.grid[z][(y-1)%6][x].F = B
                        self.grid[z][y][(x+1)%6].L = R
                        self.grid[z][y][(x-1)%6].R = L
                    elif self.direction == 'R':
                        self.grid[z][y][(x+1)%6].L = F
                        self.grid[z][y][(x-1)%6].R = B
                        self.grid[z][(y-1)%6][x].F = R
                        self.grid[z][(y+1)%6][x].B = L

                    self.grid[(z+1)%6][y][x].D = U
                    self.grid[(z-1)%6][y][x].U = D

                    self.grid[z][y][x].x = x
                    self.grid[z][y][x].y = y
                    self.grid[z][y][x].z = z

                    # move forward, turn left, and move forward again to join the next row (ie j++)
                    if x == 5:
                        assert(self.direction == 'R')
                        move('F')
                        move('L')
                        info(move('F'))
                        self.direction = 'F'
                                    
                    # turn right, move forward, and turn left to get in ini view
                    elif x == 0:
                        assert(self.direction == 'F')
                        info(move('R'))
                        move('F')
                        # we point to the Right wall
                        self.direction = 'R'
                    else:
                        assert(self.direction == 'R')
                        move('F')

                    info(str(self.grid[z][y][x]))
            assert(self.direction == 'F')
            info(move('U'))  

    def check(self):
        for z in range(6):
            for y in range(6):
                for x in range(6):
                    info(f'Checking x {x} y {y} z {z} direction {self.direction}')
                    if self.grid[z][y][x].is_coprime():
                        info(check())
                        success(f'Coprime found: {str(self.grid[z][y][x])}')

                     # move forward, turn left, and move forward again to join the next row (ie j++)
                    if x == 5:
                        assert(self.direction == 'R')
                        move('F')
                        move('L')
                        move('F')
                        self.direction = 'F'
                                    
                    # turn right, move forward, and turn left to get in ini view
                    elif x == 0:
                        assert(self.direction == 'F')
                        move('R')
                        move('F')
                        # we point to the Right wall
                        self.direction = 'R'
                    else:
                        assert(self.direction == 'R')
                        move('F')

                    info(str(self.grid[z][y][x]))
            assert(self.direction == 'F')
            move('U')  

    def is_complete(self):
        for z in range(6):
            for y in range(6):
                for x in range(6):
                    if not self.grid[z][y][x].is_complete():
                        info(f'not complete: {str(self.grid[z][y][x])}')
                    
class Room:
    R = 0
    L = 0
    F = 0
    B = 0
    U = 0
    D = 0

    def __init__(self, x, y, z):
        self.x = x
        self.y = y
        self.z = z

    def __str__(self) -> str:
        return f'x: {self.x}, y: {self.y}, z: {self.z}, R: {self.R}, L: {self.L}, F: {self.F}, B: {self.B}, U: {self.U}, D: {self.D}'

    def is_coprime(self) -> bool:
        l = [self.R, self.L, self.F, self.B, self.U, self.D]

        for i, l1 in enumerate(l):
            for _, l2 in enumerate(l[i+1:]):
                if l1 == l2:
                    error(f'doublon in the lables: {str(self)}')
                    exit(1)
                
                # this should happend if we haven't went through the cube correctly, but we choose to ignore it ftm
                if l1 == 0 or l2 == 0:
                    continue

                if bltin_gcd(l1, l2) != 1:
                    return False
                
        return True
    
    def is_complete(self) -> bool:
        if self.R == 0 or self.L == 0 or self.F == 0 or self.B == 0 or self.U == 0 or self.D == 0:
            return False
        return True
    
# test_room = Room()
# test_room.R = 0
# test_room.L = 3
# test_room.F = 5
# test_room.B = 7
# test_room.U = 11
# test_room.D = 13
# info(test_room.is_coprime())


r = remote(HOST, PORT)

cube = Cube()
cube.play()
cube.is_complete()
cube.check()

# TUCTF{F34R_P4R4N014_5U5P1C10N_D35P3R410N_Esjc0rPj3K4}