# Cleithrophobia - idekCTF 2022 (crypto, 58 solved, 472p)

## Introduction
Cleithrophobia is a crypto task.

An archive containing a Python script is given.

## Reverse engineering
The script provides an encryption oracle for a custom algorithm.

The algorithm generates a 16-bytes IV, and appends the padded input to it.
```python
pad_msg = pad(msg, 16)
blocks = [os.urandom(16)] + [pad_msg[i:i+16] for i in range(0,len(pad_msg),16)]
```

It then encrypts every block of the input and xor it with the block before.
```python
itm = [blocks[0]]
for i in range(len(blocks) - 1):
    tmp = AES.new(key, AES.MODE_ECB).encrypt(blocks[i+1])
    itm += [bytes(j^k for j,k in zip(tmp, blocks[i]))]
```

Every block is then decrypted in reverse order and xored with the block after.
```python
cip = [blocks[0]]
for i in range(len(blocks) - 1):
    tmp = AES.new(key, AES.MODE_ECB).decrypt(itm[-(i+1)])
    cip += [bytes(j^k for j,k in zip(tmp, itm[-i]))]
```

The output of this algorithm is the previous list of blocks reversed.
```python
return b"".join(cip[::-1])
```

At startup, the flag is encrypted and sent to the user.
```python
print(f"|\n|    flag = {encrypt(FLAG, KEY).hex()}")
```

The key is generated randomly and reused for every operations.
```python
KEY = os.urandom(32)
```

## Analysis
Assuming a message with at least 3 blocks `d1`..`d3` and a padding block `PP`,
the state of the algorithm is the following:
```
itm = [
        iv,
        enc(d1) ^ iv,
        enc(d2) ^ d1,
        enc(d3) ^ d2,
        enc(PP) ^ d3,
]

cip = [
        iv,
        dec(itm[-1]) ^ itm[-0],
        dec(itm[-2]) ^ itm[-1],
        dec(itm[-3]) ^ itm[-2],
        dec(itm[-4]) ^ itm[-3],
]

cip = [
        iv,
        dec(enc(PP) ^ d3) ^ iv,
        dec(enc(d3) ^ d2) ^ enc(PP) ^ d3,
        dec(enc(d2) ^ d1) ^ enc(d3) ^ d2,
        dec(enc(d1) ^ iv) ^ enc(d2) ^ d1,
]
```

When `d1 = 0`,
```
cip[3] = dec(enc(d2) ^ d1) ^ enc(d3) ^ d2
       = dec(enc(d2)) ^ enc(d3) ^ d2
       = d2 ^ enc(d3) ^ d2
       = enc(d3)
```
This property can be used to encrypt any block with the secret key.

When `d2 = 0` and `d1 = enc(d2) ^ X`,
```
cip[3] = dec(enc(d2) ^ d1) ^ enc(d3) ^ d2
       = dec(enc(d2) ^ enc(d2) ^ X) ^ enc(d3) ^ d2
       = dec(X) ^ enc(d3)
```
This property can be used to decrypt any block with the secret key.


## Decryption
Armed with a way to encrypt and decrypt arbitrary blocks, it is possible to
revert the encryption algorithm by essentially running the algorithm in reverse.

**Flag**: `flag{wh0_3v3n_c0m3s_up_w1th_r1d1cul0us_sch3m3s_l1k3_th1s__0h_w41t__1_d0}`


## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
const LOCAL = false;
const HOST  = "cleithrophobia.chal.idek.team";
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

function send($fp, string $str) : string
{
	expectLine($fp, "|");
	expectLine($fp, "|  ~ Want to encrypt something?");
	expectLine($fp, "|");
	expect($fp, "|    > (hex) ");

	fwrite($fp, bin2hex($str) . "\n");

	expectLine($fp, "|");
	expect($fp, "|   ");

	return hex2bin(line($fp));
}

function blocks($fp, string $str) : array
{
	$bin    = send($fp, $str);
	$blocks = str_split($bin, 0x10);
	return array_reverse($blocks);
}

function encrypt($fp, string $block) : string
{
	if(0x10 !== strlen($block))
		throw new Exception("Size of block is wrong");

	$data   = str_repeat("\x00", 0x10 * 2) . $block;
	$blocks = blocks($fp, $data);
	assert(5 === sizeof($blocks));

	return $blocks[3];
}

function decrypt($fp, string $block) : string
{
	if(0x10 !== strlen($block))
		throw new Exception("Size of block is wrong");

	static $enc;

	if(!$enc)
		$enc = encrypt($fp, str_repeat("\x00", 0x10));

	$block ^= $enc;

	$data   = $block . str_repeat("\x00", 0x10 * 2);
	$blocks = blocks($fp, $data);
	assert(5 === sizeof($blocks));

	return $blocks[3] ^ $enc;
}

printf("[*] Opening connection\n");
$time = microtime(true);

$fp = fsockopen(HOST, PORT);

if(!LOCAL)
	expectLine($fp, "== proof-of-work: disabled ==");

for($i = 0; $i < 13; $i++)
	line($fp);

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

expect($fp, "|    flag = ");
$flag = hex2bin(line($fp));

$blocks = array_reverse(str_split($flag, 0x10));

for($i = 1; $i < sizeof($blocks); $i++) {
	$blocks[$i] ^= $blocks[$i - 1];
	$blocks[$i]  = encrypt($fp, $blocks[$i]);
}

for($i = 1; $i < sizeof($blocks); $i++) {
	$j = sizeof($blocks) - $i;
	$blocks[$j] ^= $blocks[($j + 1) % sizeof($blocks)];
	$blocks[$j]  = decrypt($fp, $blocks[$j]);
}

$blocks = array_reverse($blocks);
array_pop($blocks); // IV

// Remove padding
$last = array_pop($blocks);
$last = substr($last, 0, ord($last[strlen($last) - 1]));
$blocks[] = $last;

$flag = implode("", $blocks);
printf("%s\n", $flag);
```
