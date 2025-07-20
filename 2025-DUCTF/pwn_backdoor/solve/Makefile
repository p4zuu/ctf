CC=musl-gcc
AS=as
LD=ld
OBJCOPY=objcopy

all: shellcode pwn

pwn:
	$(CC) solve.c -o pwn -static

shellcode:
	$(AS) pwn.S -o sc.o
	$(LD) sc.o -N -o sc	
	$(OBJCOPY) -O binary --only-section=.text sc sc.bin

clean:
	rm -f pwn sc sc.bin sc.o
