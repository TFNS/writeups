CC=aarch64-linux-musl-gcc
AS=aarch64-linux-gnu-as
LD=aarch64-linux-gnu-ld
OBJCOPY=aarch64-linux-gnu-objcopy

all: shellcode pwn

pwn:
	$(CC) solve.c -o pwn -static

shellcode:
	$(AS) pwn.S -o sc.o
	$(LD) sc.o -N -o sc	
	$(OBJCOPY) -O binary sc sc.bin

clean:
	rm -f pwn sc sc.bin sc.o
