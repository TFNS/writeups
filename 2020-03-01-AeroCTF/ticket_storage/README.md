# Ticket Storage - Aero CTF 2020 (pwn, 366p, 30 solved)
## Introduction

Ticket Storage is a pwn/reverse task.

An archive containing a binary, a libc and its corresponding loader (`ld.so`).

The binary exits instantly when run.

## Reverse engineering

As stated in the introduction, the binary exists as soon as is it started.

`strace` is a quick way to figure out what a program does in order to understand
why it does not work.

```
% strace ./ticket_storage
execve("./ticket_storage", ["./ticket_storage"], 0x775998d1d9e0 /* 47 vars */) = 0
[...]
openat(AT_FDCWD, "/tmp/flag.txt", O_RDONLY) = -1 ENOENT (No such file or directory)
exit_group(-1)                          = ?
+++ exited with 255 +++
```

It looks like the program tries to open `/tmp/flag.txt` which does not exists on
the local system, and then exits.

The program lets a user create, view and delete flight tickets. The user can
only see tickets they own. The user can change its name.

The program reads information from `/tmp/flag.txt` and adds it to the ticket
list. This part of the program is somewhat hidden in `_INIT-1`, a function
declared as a constructor, which gets called before `main`.

## Exploitation

The vulnerability lies in the way the user's name is compared to each entry's
owner in the function that displays tickets.

```c
if(0 == memcmp(t->ticket->owner, name, nameLen))
	ticket_print(t->ticket);
```

With `name` and `nameLen` defined during initialisation to user-specified input.

It is possible to have a name of size 0 by sending no name.

This will transform the check in `0 == memcmp(t->ticket->owner, "", 0)` which is
always satisfied. Every tickets will be printed, including the one that contains
the flag.

```
{?} Enter name:
-------- Ticket Storage --------
1. Reserve a ticket
2. View ticket
3. View ticket list
4. Delete ticket
5. Change name
6. Exit
> 3
---- Ticket qW3Kto$a ----
From: flag_is
To: Aero{4af2aea9b7dea9aabbc1c9a423e4957fd4c615821f4ded0f618b629651a9d67c}
Date: 13371337
Cost: 31337
Owner: sup3rs3cr3tus3rn4m3$4lted
```

**Flag**: `Aero{4af2aea9b7dea9aabbc1c9a423e4957fd4c615821f4ded0f618b629651a9d67c}`
