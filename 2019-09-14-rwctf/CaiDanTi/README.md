# caidanti (flag 1) - Real World CTF 2019 Quals

## Introduction

The caidanti is a serie of two tasks. The first one is a reverse/shellcoding
task and the second is a pwn task.

This writeup only deals with the first part.

The archive given contains a virtual machine and two ELF file. One of them,
`caidanti` provides a server on port 31337. This server contains an option that
executes a given shellcode.

The binary does not run on Linux: it runs on Google's Fuchsia OS.


## Particularities

Being able to execute shellcode, a pwner's first instinct is to go for the
`/bin/sh`. Fuchsia is a pretty good OS in terms of security: the `syscall`
instruction is trapped by the OS, which kills the task if the instruction
pointer is not at a whitelisted location.

Using a ret2libc attack, it was not possible to execute `/bin/sh`, nor
`/boot/bin/sh`, nor anything else.

Using a combination of `open` and `printf`, we figured the sad state of the
reality: no files can be executed because there is no file. Fuchsia starts the
task in a very secure jail.

It's at this moment we realized that this is a reversing/shellcode task and not
a pwn/shellcode task.


## Reverse engineering

After making sense of the Fuchsia environment, the task becomes clear.  There
are two binaries: `caidanti` and `caidanti-storage-service`. The first one is
the server. It sends IPC requests to the service. The service then answers.

One of the IPC call is `SecretStorageGetFlag1Request`, it must be called from
the shellcode. This request takes two arguments.

```
$ strings caidanti | grep -i flag
fidl.caidanti.storage/SecretStorageGetFlag1Response
that's safe, because THERE IS NO FLAG!
Sanity check failed: there should be no flag.
/pkg/data/flag
fidl.caidanti.storage/SecretStorageGetFlag1Request
```

Reversing the service helps understand what the two arguments are: the first one
is a password, and the second one is the output value.

The service runs a reversible algorithm. Reversing the algorithm gives the
password (0x416564614D756F59, 0x6C6C61434C444946), or `YouMadeAFIDLCall`.

**Flag**: `rwctf{Turns_out_this_is_harder_than_expected}`


## Appendices

### pwn.php
The following script uploads a shellcode and reads the output until the
connection closes:
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/home/user/ctf/tools/pwn/phplib/hexdump.php";
require_once "/home/user/ctf/tools/pwn/phplib/tubes/Socket.php";

const HOST = "54.177.17.135";
const PORT = 23333;

function menu(Tube $t)
{
	$t->expectLine("");
	$t->expectLine("1. Create a new secret");
	$t->expectLine("2. Read content of secret");
	$t->expectLine("3. Update content of secret");
	$t->expectLine("4. Delete secret");
	$t->expectLine("5. List secrets");
	$t->expectLine("6. Exit");
	$t->expectLine("114514. Bring your own Cài Dān Tí");
}

function shellcode(Tube $t, $sc)
{
	menu($t);
	$t->write("114514\n");

	$t->expect("Your code size: ");
	$t->write(strlen($sc) . "\n");

	$t->write($sc);
}

printf("[*] Creating process\n");
$time = microtime(true);
$t = new Socket($argv[1] ?? HOST, (int)($argv[2] ?? PORT));

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

/* Discard motd */
for($i = 0; $i < 35; $i++)
	$t->readLine();

shellcode($t, file_get_contents("./shellcode"));

dump:
printf("[!] Dumping...\n");
while($buffer = $t->read(4096)) {
	printf("%s", $buffer);
}
```

### shellcode.S
The following shellcode calls the remote function with the correct password:
```asm
.intel_syntax noprefix

// R14 = lib
// R15 = base
_start:
	lea r15, [rbp - 0x000013fe] // Base

	mov r14, [r15 + 0x000120c0] // open gotplt
	sub r14, 0x0011af10

	xor eax, eax
	push rax
	push rax
	push rax

	lea rcx, [r15 + 0x00007f00] // secret method ?
	mov rdi, [r15 + 0x00012140] // object
	lea rsi, [rip + input]      // input
	mov rdx, rsp                // output
	call rcx

	// printf
	lea rcx, [r15 + 0x00010c40]
	lea rdi, [rip + fmt]
	mov rsi, rax
	//mov rdx, rsp
	pop rdx
	call rcx

end:
	lea rcx, [r15 + 0x00010c00] // exit
	call rcx

	ret

int3
fmt: .asciz "ret: %08lX %s\n"
input:
.ascii "YouMadeAFIDLCall"
//.quad 0x416564614D756F59, 0x6C6C61434C444946
.quad 0x1010101010101010
```

### solve.c
The following C code reverses the password encoding algorithm:
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void)
{
	uint64_t k1, k2;
	uint64_t key[0x1F];
	uint64_t l;

	k1 = 0x70697a7a6174716c;
	k2 = 0x6c7174617a7a6970;

	for(int i = 0; i < sizeof(key) / sizeof(*key); i++) {
		k2  = (k2 << 0x38) | (k2 >> 8);
		k2 += k1;
		k2 ^= i;

		k1  = (k1 << 0x03) | (k1 >> 0x3D);
		k1 ^= k2;

		key[i] = k1;
	}


	k1 = 0xc96aac2f35c3833f;
	k2 = 0x8f1fa1ad36c66f95;

	for(int i = 0; i < sizeof(key) / sizeof(*key); i++) {
		int j = sizeof(key) / sizeof(*key) - 1 - i;

		k2 ^= k1;
		k2  = (k2 >> 3) | (k2 << 0x3D);

		k1 ^= key[j];
		k1 -= k2;
		k1  = (k1 >> 0x38) | (k1 << 0x08);
	}

	l = k1 ^ k2;
	l = (l << 0x3D) | (l >> 0x03);

	k1 ^= 0x70697a7a6174716c;
	k1 -= l;
	k1  = (k1 << 0x08) | (k1 >> 0x38);

	printf("0x%16lX, 0x%16lX\n", l, k1);
}
```
