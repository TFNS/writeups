# RageQuit - BalCCon2k20 CTF (rev, 497p, 1 solved)
## Introduction

RageQuit is a reversing task.

An archive containing a Linux ELF file, its output and an encrypted file is
provided.

The output contains references to `xchacha20-poly1305` :
> send the payment reference below to poly1305@cnc-admin.com

> able to afford some x-Cha-Cha-Cha dancing lessons

## Reverse engineering
### Initialization
The main function first does a weird dance to call a function while ensuring
there is only one argument :
```c
fptr[argc](0, buffer);
```

If argc is not 1, the call will crash.

The function does pretty much nothing if the first argument is 0 : it only
prints a obfuscated message.

Then, the program prepares a regular expression : `^.+\.flag$`. It is used to
ensure only files ending with `.flag` are encrypted.

The program calls a function that calls 10 other functions... fortunately the
first one uses assertions and gives away its name : `sodium_crit_enter`.

By looking for cross-references to `sodium_crit_enter` in the source code of
Libsodium, it becomes clear that this first function is in fact `sodium_init`.

The next function cannot be easily identified (it is
`crypto_aead_xchacha20poly1305_ietf_keygen`). But the one after is a POSIX
function : `ftw` (file tree walk). It receives a callback that is called for
every file in the current directory recursively.

The callback ensures the filename matches the regex and encrypt the file if it
does.

### Encryption routine

The encryption can be roughly decompiled to :
```c
FILE *fp_in  = fopen(filename, "rb+");
FILE *fp_out = fopen(outname, "wb");
FILE *fp_rng = fopen("/dev/urandom", "r");
char buffer[0x1000]

unlink(filename);

while(1) {
	size = fread(buffer, 1, sizeof(buffer), fp_in);
	if(feof(fp_in))
		break;

	/* encrypt and write the output */
	encrypt(buffer);
	fwrite(buffer, size, 1, fp_out);

	/* rewind and overwrite with garbage */
	fseek(fp_in, -size, SEEK_CUR);
	fread(buffer, size, 1, fp_rng);
	fwrite(buffer, size, 1, fp_in);

}

/* encrypt and write the output */
encrypt(buffer);
fwrite(buffer, size, 1, fp_out);

/* rewind and overwrite with garbage */
fseek(fp_in, -size, SEEK_CUR);
fread(buffer, size, 1, fp_rng);
fwrite(buffer, size, 1, fp_in);
```

By using a mix of Libsodium source code, documentation and assumption, it is
possible to identify the exact name of the encryption function.

The ransomware encrypts files using
`crypto_secretstream_xchacha20poly1305_push`, just like in the
[Encrypted streams and file encryption](https://doc.libsodium.org/secret-key_cryptography/secretstream)
chapter.

It is therefore safe to assume that the key is generated in the `main` function
by the `crypto_aead_xchacha20poly1305_ietf_keygen` function and is stored at
`0x000387c0`.

The nonce (header) is generated randomly and is stored in the first 0x18 bytes
of the encrypted file :
```c
crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
fwrite(header, 0x18, 1, fp_oput);
```

### Reference generation

Once every files matching the regular expression have been encrypted, the
program calls once again the weird `fptr` function with different arguments :
`fptr[argc](1, key = buffer)`.

When the first argument is 1, the function does something entirely different.

It first starts by copying the key in a local buffer, and shift every byte left
according to a lookup-table :
```c
int keyLocal[sizeof(key)];
int shifts[8] = {...};

for(i = 0; i < sizeof(key); i++) {
	keyLocal[i] = key[i];
	keyLocal[i] = keyLocal[i] << (shifts[j % 8] & 0x1f);
}
```

It then calls 3 functions in this order, and with these arguments :
```c
f_2640(keyLocal, 4);
f_3d60(keyLocal, 1);

f_2640(keyLocal, 2);
f_3d60(keyLocal, 6);

f_2640(keyLocal, 5);
f_3d60(keyLocal, 4);

f_4450(keyLocal);
```

`f_2640` calls differents functions through trampolines. All of these functions
take two arguments : an `int*` (always `keyLocal` and an index. This index
goes from `0x00` to `0x10`.

All these functions add the `arg2`th number of a look-up table to `arg1[idx]`.
`idx` increases by one for each function.

The `f_2640` function effectively adds a look-up table to the key.

`f_3d60` is much more straightforward because it does not use trampolines and
new functions :
```c
localKey[0] = localKey[0] * LUT_mul[start + 0 & 0xf];
localKey[1] = localKey[1] * LUT_mul[start + 1 & 0xf];
localKey[2] = localKey[2] * LUT_mul[start + 2 & 0xf];
localKey[3] = localKey[3] * LUT_mul[start + 3 & 0xf];
// ...
```

This function does the same action but multiplies instead of adding. The look-up
table is different.

`f_4450` is also straightforward : it xors `localKey[0x01..0x1F]` with
`localKey[0x00..0x1E]`

The full algorithm has been reimplemented in the `check.php` script present in
the appendices of this writeup.

### Undoing the transformation

The last xor operation can be reverted.

Unfortunately the multiplication operation cannot be reverted because 8 is a
possible factor because there is no multiplicative inverse of 8 mod 2^32.

The multiplication, addition and shift operations only work on a specific index.
This means that once the xor operation has been reverted, it is possible to
bruteforce each byte of the key (256 possibilities) independently.

The code to recover the key is in `pwn.php`

The encryption key is `AF 51 23 A0 B0 14 C3 CC CF D4 8B 47 6D E9 08 98 54 DB C8
8C 49 1E 54 44 35 C4 D5 3B FA 8E FD 3A`

Once the key is recovered, it is possible to decrypt the `ragequit.flag.rgq`
file. This file contains the flag.

**Flag**: `BCTF{s0m3t1m2s_r4g3_1s_4ll_y0u_n33d}`

## Appendices
### check.php
```php
<?php
const SHL = [
	0x0F, 0x0B, 0x0A, 0x0F,
	0x02, 0x0D, 0x08, 0x09,
];

const ADD = [
	0x75, 0x6B, 0xC5, 0x91,
	0x76, 0x94, 0xA0, 0x69,
	0x90, 0xB2, 0x6D, 0x81,
	0x9E, 0xAA, 0x65, 0x66,
];

const MUL = [
	0x0B, 0x05, 0x08, 0x08,
	0x08, 0x0F, 0x0F, 0x01,
	0x0E, 0x09, 0x0A, 0x05,
	0x09, 0x0D, 0x0F, 0x0C,
];

function shl($key)
{
	for($i = 0; $i < sizeof($key); $i++) {
		$key[$i] <<= SHL[$i % sizeof(SHL)];
		$key[$i] &= 0xFFFFFFFF;
	}

	return $key;
}


function add($key, $start)
{
	for($i = 0; $i < sizeof($key); $i++) {
		$key[$i] += ADD[($i + $start) % sizeof(ADD)];
		$key[$i] &= 0xFFFFFFFF;
	}

	return $key;
}

function mul($key, $start)
{
	for($i = 0; $i < sizeof($key); $i++) {
		$key[$i] *= MUL[($i + $start) % sizeof(MUL)];
		$key[$i] &= 0xFFFFFFFF;
	}

	return $key;
}

$key = [
	0xb4, 0x68, 0x9b, 0xfc, 0x6e, 0xcb, 0xd4, 0x20,
	0x70, 0x54, 0x3d, 0xbf, 0x7e, 0xe2, 0x7a, 0x2a,
	0x96, 0xd0, 0x0d, 0x68, 0xf1, 0x02, 0x5a, 0xdf,
	0xa1, 0x2d, 0xf0, 0xc8, 0x69, 0x16, 0xcd, 0xe9,
];

$key = shl($key);
$key = add($key, 4);
$key = mul($key, 1);
$key = add($key, 2);
$key = mul($key, 6);
$key = add($key, 5);
$key = mul($key, 4);

/* last xor */
for($i = 1; $i < sizeof($key); $i++)
	$key[$i] ^= $key[$i - 1];

for($i = 0; $i < 8; $i++) {
	for($j = 0; $j < 4; $j++)
		printf("%08X ", $key[$i * 4 + $j]);
	printf("\n");
}

$check = [
	0xd2f17588, 0xd37722b7, 0xdc9e6244, 0xffee4108,
	0xfffd56d4, 0xbd175d74, 0xbd5db888, 0xbdb8c25e,
	0xb473ef09, 0xa470b0a4, 0xa764b5e9, 0x6e17b195,
	0x6e1d4ffc, 0x2c2a416d, 0x2d5a31a5, 0x2cee7025,
	0x832705ad, 0x802b5292, 0x81729261, 0x8fd2b12d,
	0x8ff15361, 0x8f5bf8c1, 0x8f7bf93d, 0x8948a7eb,
	0xf75a0abc, 0xffcc1511, 0xf3db645c, 0x212a6020,
	0x2123e729, 0x2750e9b8, 0x25399970, 0x2c5c68f0,
];

for($i = 0; $i < 32; $i++)
	if($key[$i] !== $check[$i])
		printf("! %02X %08X %08X\n", $i, $key[$i], $check[$i]);
```

### pwn.php
```php
<?php
const SHL = [
	0x0F, 0x0B, 0x0A, 0x0F,
	0x02, 0x0D, 0x08, 0x09,
];

const ADD = [
	0x75, 0x6B, 0xC5, 0x91,
	0x76, 0x94, 0xA0, 0x69,
	0x90, 0xB2, 0x6D, 0x81,
	0x9E, 0xAA, 0x65, 0x66,
];

const MUL = [
	0x0B, 0x05, 0x08, 0x08,
	0x08, 0x0F, 0x0F, 0x01,
	0x0E, 0x09, 0x0A, 0x05,
	0x09, 0x0D, 0x0F, 0x0C,
];

function shl($key)
{
	for($i = 0; $i < sizeof($key); $i++) {
		$key[$i] <<= SHL[$i % sizeof(SHL)];
		$key[$i] &= 0xFFFFFFFF;
	}

	return $key;
}


function add($key, $start)
{
	for($i = 0; $i < sizeof($key); $i++) {
		$key[$i] += ADD[($i + $start) % sizeof(ADD)];
		$key[$i] &= 0xFFFFFFFF;
	}

	return $key;
}

function mul($key, $start)
{
	for($i = 0; $i < sizeof($key); $i++) {
		$key[$i] *= MUL[($i + $start) % sizeof(MUL)];
		$key[$i] &= 0xFFFFFFFF;
	}

	return $key;
}

$key = [
	0x887515cd, 0xb76225cc, 0x4422becf, 0x08013ed9,
	0x748c25d9, 0xd4e7bcdf, 0x280cf8df, 0xfe4654da,
	0xa9eb6f31, 0x04b40c19, 0x49c90d1e, 0x35cdee54,
	0xbc03e754, 0x2d0da310, 0xe57db910, 0x65dc9b16,
	0xeda9ea74, 0xd23edf77, 0x21be5963, 0x6d9de970,
	0xa1c4e770, 0x01ef0279, 0xfd0a1f79, 0x2b60fa78,
	0x7ccd3205, 0xd1926520, 0x9cf7de2a, 0xe0f3e514,
	0x0955f614, 0x985b6d3d, 0x502b943f, 0xd06acd3d,
];

// flip
$key = array_map(function($x) {
	$bin = pack("V", $x);
	return unpack("N", $bin)[1];
}, $key);

$result = [
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
];

/* last xor */
for($i = sizeof($key) - 1; $i > 0; $i--)
	$key[$i] ^= $key[$i - 1];

// bf
for($i = 0; $i < 0x100; $i++) {
	$check = [
		$i, $i, $i, $i, $i, $i, $i, $i,
		$i, $i, $i, $i, $i, $i, $i, $i,
		$i, $i, $i, $i, $i, $i, $i, $i,
		$i, $i, $i, $i, $i, $i, $i, $i,
	];

	$check = shl($check);
	$check = add($check, 4);
	$check = mul($check, 1);
	$check = add($check, 2);
	$check = mul($check, 6);
	$check = add($check, 5);
	$check = mul($check, 4);

	for($j = 0; $j < sizeof($check); $j++)
		if($key[$j] === $check[$j])
			$result[$j] = $i;
}

for($i = 0; $i < sizeof($result); $i++)
	printf("%02X", $result[$i]);

printf("\n");
```

### crypto.php
```
<?php
$key   = "AF5123A0B014C3CCCFD48B476DE9089854DBC88C491E544435C4D53BFA8EFD3A";
$key   = hex2bin($key);

$file  = file_get_contents("ragequit.flag.rgq");
$nonce = substr($file, 0, 0x18);
$data  = substr($file, 0x18);

$state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($nonce, $key);
$ret   = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $data);

var_dump($ret);
```
