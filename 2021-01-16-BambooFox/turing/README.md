# TuringMachineDiagram - BambooFox CTF 2021 (reverse, 500p)

## Introduction
TuringMachineDiagram is a reverse task.

Two host/port combinations are given:
- chall.ctf.bamboofox.tw:7619
- chall.ctf.bamboofox.tw:7719

A build of `libc.so.6` and `ld-linux-x86-64.so.2` from the 2.32 version of glibc
are also provided.

## Servers
The first server (port 7619) spits binary data. This is an x64 ELF file. The
file is regularly changed.

The second server (port 7719) waits for input. If the input is invalid, it
prints the following message:
```
Wrong key, I can only give you flag in exponential time :(
f[...]Connection Timeout.
```

The goal of this challenge is to retrieve a binary from the first server, crack
it automatically and send the key to the second server.

## Binary diffing
Since the server sends different binaries, it is a good idea to compare two
binaries early.

In this case, there are 3 information that differ:
- The ELF build ID
- Two 32-bits words in the program's text
- A huge chunk of data

The two 32-bits words are used in comparisons, in the `decrypt` function:
```assembly
1447:       48 81 7d b0 e6 1d 4e 25   cmp    QWORD PTR [rbp-0x50],0x254e1de6
144f:       75 0a                     jne    145b <decrypt+0x14b>

1451:       48 81 7d b8 74 38 66 21   cmp    QWORD PTR [rbp-0x48],0x21663874
1459:       74 0a                     je     1465 <decrypt+0x155>
```

## Reverse engineering
The binaries are sent with debug symbols. Every functions and global variables
have a meaningful name.

The binary first sets `libcbase` to `scanf - 0x59F60`. This corresponds to the
offset of `scanf` in the provided libc.

It then allocates `roplen` 64-bits integers and populates it with the long chunk
of data that differs between binaries.

The binary calls `decrypt`, relocates some integers by adding `libcbase` to
them, changes its stack pointer to `rope` and  jumps to `libc + 0x26697` (a
single `ret` instruction)

It is safe to assume that the huge chunk of data is an encrypted ROP chain that
will be executed by the binary.

## Decrypt
The `decrypt` function reads a secret of size 40, and calculates two checksums
out of it:
```c
uint64_t chk1 = 0;
uint64_t chk2 = 0;

for(size_t i = 0; i < 40; i++) {
	chk1 = (0x13f * chk1 + pass[i]) % 0x3b9af9bb;
	chk2 = (0x179 * chk2 + pass[i]) % 0x3b9aca07;
}
```

The two checksums are then compared to the two 32-bits integers that differ
between each binaries.

If the checksums pass, the ROP chain is decrypted as follows:
```c
for(size_t i = 0; i < ropelen; i += 2) {
	uint8_t *p = (uint8_t*)(rope + i);

	p[0] ^= 0xF9;
	p[1] ^= pass[(i / 2) % 40];
}
```

Additionnally, if the final 64-bits integer has one of the bits 56 to 59 set, it
will remove the mask and relocate it against libc.
```c
#define LIBC_MASK (0x0F00000000000000ll)

for(size_t i = 0; i < ropelen; i += 8) {
	uint64_t *gadget = rope + i;

	if(0 != (*gadget & LIBC_MASK)) {
		*gadget ^= LIBC_MASK;
		*gadget += libc_base;
	}
}
```

Strictly speaking, this relocation is not within the `decrypt` function. But the
author of this write-up consider this snippet of code as being part of the
decryption routine.

## Recovery of the key
The key has 40 characters. A brute-force attack would be too long.

The blob of data can be attacked like a casual xor-cipher with a repeating key.

The size of the password is known (40), but every even bytes are xored with
`0xF9`. This means the key is repeated every 80 bytes (every 10 64-bits
integers).

For each 64-bit integer `hh gg ff ee dd cc bb aa`, the original value of `aa`,
`cc`, `ee` and `gg` can be found by simple xors.

Since most integers are referring to a libc address, it is safe to assume that
bytes `hh`, `gg`, `ff`, `ee` and `dd` are 0. (after a xor with `LIBC_MASK`)

3/4th of the key can be recovered by taking `hh`, `ff`, and `dd` of words whose
`gg` and `ee` are 0.

The last bytes of the key are harder to find. Some bytes can be recovered by
assuming that values decrypted as `00 00 00 00 00 00 ?? 00` are 0. Some bytes
can be recovered by looking for repeating gadgets.

## ROP chain
The ROP chain reads a new string. It then computes the difference between the
first and the second inputs.

```
Input some secret to generate the TM who can verify itself in polynomial time.
key{csM1qA1YajAsg_PDXgjHDEd1tmJbFtkpIwo}
test
The comparasion result between the key and your input is: 4058265758821296551.
```

Only an idiot would waste time writing a disassembler for this ROP chain only to
realize they could have simply read what the binary said.

## Automation
The first goal of this challenge was to automate the decryption of a random
binary. Now that the blob of data has been decrypted once, it becomes very easy
to recover the key of any binary using a known-plaintext attack.

The series of 10 gadgets at offset 2000 is particularly interesting to perform a
KPA.

**Flag**: `flag{Th1s_1s_a_p0lyn0m14l_71m3_R0P_pr3par3d_f0r_y0ur_A_plus_n3x7_year}`

## Appendices
### xor.php
```php
<?php
$fp = fopen("7619", "r");
fseek($fp, 0x2098, SEEK_SET);

// found with script
$pass  = str_replace(" ", "\x00", " ey  sM  A1  jA  _P  gj  Ed  mJ  tk  wo ");
$pass ^= str_replace(" ", "\x00", "k  {c  1q  Ya  sg  DX  HD  1   bF  pI  }");

$pass  = "key{csM1qA1YajAsg_PDXgjHDEd1tmJbFtkpIwo}";

for($i = 0; $i < 278; $i++) {
	$a = ord(fgetc($fp));
	$b = ord(fgetc($fp));
	$c = ord(fgetc($fp));

	$d = ord(fgetc($fp));
	$e = ord(fgetc($fp));
	$f = ord(fgetc($fp));
	$g = ord(fgetc($fp));
	$h = ord(fgetc($fp));

	/* Those bytes are always xored with 0xF9 */
	$a ^= 0xF9;
	$c ^= 0xF9;
	$e ^= 0xF9;
	$g ^= 0xF9;

	/* e and g are 0... so d and f are probably 0 too */
	if($e === 0 && $g === 0) {
		$idx = (4 * $i + 1) % 40;
		if($pass[$idx] !== "\x00" && $pass[$idx] !== chr($d))
			throw new Exception("bad d");

		$pass[$idx] = chr($d);

		$idx = (4 * $i + 2) % 40;
		if($pass[$idx] !== "\x00" && $pass[$idx] !== chr($f))
			throw new Exception("bad f");


		$pass[$idx] = chr($f);
	}

	/* xor with what we know */
	$b ^= ord($pass[(4 * $i + 0) % 40]);
	$d ^= ord($pass[(4 * $i + 1) % 40]);
	$f ^= ord($pass[(4 * $i + 2) % 40]);
	$h ^= ord($pass[(4 * $i + 3) % 40]);

	// if($h & 0x0F)
	// 	$h ^= 0x0F;

	/* pretty hex dump */
	printf("%02X%02X %02X%02X %02X%02X %02X%02X",
		$h, $g, $f, $e, $d, $c, $b, $a);

	if(9 === ($i % 10))
		printf("\n");
	else
		printf(" | ");
}
printf("\n");
printf("%s\n", str_replace("\x00", " ", $pass));
```

### disass.php
```php
#!/usr/bin/php
<?php
$fp = STDIN;

$LUT = [
	0x9F519  => [0, "xor rax, rax"],
	0x27B15  => [1, "pop rdi (%s)"],
	0x29D8F  => [1, "pop rsi (%s)"],
	0xFB841  => [2, "pop rdx (%s)\npop r12 (%s)"],
	0x59F5A  => [0, "syscall"],
	0xE6BCE  => [2, "pop rcx (%s)\npop rbx (%s)"],
	0x40780  => [1, "pop rax"],
	0x4B981  => [0, "sub byte [rcx+1], al"],
	0x11EFD8 => [0, "xor r10d, r10d\nmov eax, r10d"],
	0x3B75E  => [0, "add r10, qword [rdi+0x20]\nmov rax, r10"],
	0x3B762  => [0, "mov rax, r10"],
	0x3252F  => [1, "pop rbx (%s)"],

	0x28BA7  => [0, "???"],

	0x58E30  => [0, "call dprintf"],
	0x3FF40  => [0, "call exit"],
];

function getLong($fp) : array
{
	$long = fread($fp, 8);
	if(8 !== strlen($long))
		throw new Exception("EOF");


	$number = unpack("Q", $long)[1];
	$flags  = $number & 0x0F00000000000000;
	$value  = $number & 0x00FFFFFFFFFFFFFF;

	return [$flags, $value];
}

while(true) {
	try {
		[$flags, $value] = getLong($fp);
	} catch(Exception $e) {
		break;
	}

	/* not instruction */
	if(0 === $flags) {
		printf("value: %X\n", $value);
		continue;
	}

	/* Unknown */
	if(!isset($LUT[$value])) {
		printf("UNK: %X\n", $value);
		continue;
	}

		
	[$count, $ins] = $LUT[$value];

	$params = [];
	for($i = 0; $i < $count; $i++) {
		[$flags, $value] = getLong($fp);

		if(0 === $flags)
			$params[] = sprintf("0x%016X", $value);
		else
			$params[] = sprintf("libc + 0x%08X", $value);

	}

	vprintf($ins, $params);
	printf("\n");
}
```

### findKey.php
```php
<?php
$fp = fopen($argv[1], "r");
fseek($fp, 0x2098, SEEK_SET);
fseek($fp, 250 * 8, SEEK_CUR);

$clear = [
	0x7B, 0x00, 0x00, 0x0F,
	0x5E, 0x00, 0x00, 0x0F,
	0xB7, 0x00, 0x00, 0x0F,
	0x7B, 0x00, 0x00, 0x0F,
	0x5E, 0x00, 0x00, 0x0F,
	0xB7, 0x00, 0x00, 0x0F,
	0x7B, 0x00, 0x00, 0x0F,
	0x5E, 0x00, 0x00, 0x0F,
	0xB7, 0x00, 0x00, 0x0F,
	0x7B, 0x00, 0x00, 0x0F,
];

$pass = "";
for($i = 0; $i < 10; $i++) {
	$a = ord(fgetc($fp));
	$b = ord(fgetc($fp));
	$c = ord(fgetc($fp));

	$d = ord(fgetc($fp));
	$e = ord(fgetc($fp));
	$f = ord(fgetc($fp));
	$g = ord(fgetc($fp));
	$h = ord(fgetc($fp));

	$pass .= chr($b ^ $clear[4 * $i + 0]);
	$pass .= chr($d ^ $clear[4 * $i + 1]);
	$pass .= chr($f ^ $clear[4 * $i + 2]);
	$pass .= chr($h ^ $clear[4 * $i + 3]);
}

printf("%s\n", $pass);
```
