# babyrev - Balsn CTF 2020 (rev, 310p, 33 solved)
## Introduction

This challenge consists of few Scala classes.
The decompiled classes show that the code xors a byte array with a data stream.
The implementation of this data stream is missing.

## Key size

It is possible to recover the size of the key by looking at patterns in the 8th
bit of the xored data:

```
% ./msb.php | xxd -c 8 | sed 's/ 00/   /g'
00000000:       80    80 80    80  ........
00000008:       80    80 80    80  ........
00000010:       80    80 80    80  ........
00000018:       80    80 80    80  ........
00000020:       80    80 80    80  ........
00000028:       80    80 80    80  ........
00000030:       80    80 80    80  ........
00000038:       80    80 80        .......
```

```php
<?php
$a = [71, 20, -82, 84, -45, -4, 25, -122, 77, 63, -107, 13, -111, -43, 43, -42,
96, 38, -88, 20, -67, -40, 79, -108, 77, 8, -75, 80, -45, -69, 25, -116, 117,
106, -36, 69, -67, -35, 79, -114, 113, 36, -112, 87, -67, -2, 19, -67, 80, 42,
-111, 23, -116, -55, 40, -92, 77, 121, -51, 86, -46, -85, 93];

foreach($a as $n)
	echo chr(0x80 & $n);
```

## Partial key recovery

It is possible to infer information about the key by assuming that:
- the key length is 8 (and not a multiple of 8 such as 16 or 24),
- the output contains only characters in a specific charset

```
% ./find.php
[...]
1 4B: _tmC!oa2
2 FD: ShUH!ml0
3 64: 0ip4!3s2
[...]
6 7C: eW3e3oT!
```

There is only one possibility for the 2nd, 3rd, 4th and 6th characters of the key.
The key is thus : `?? 4B FD 64 ?? ?? 7C ??`

```php
<?php
function isValid($str)
{
	$valid = [
		"a" => true, "b" => true, "c" => true, "d" => true,
		"e" => true, "f" => true, "g" => true, "h" => true,
		"i" => true, "j" => true, "k" => true, "l" => true,
		"m" => true, "n" => true, "o" => true, "p" => true,
		"q" => true, "r" => true, "s" => true, "t" => true,
		"u" => true, "v" => true, "w" => true, "x" => true,
		"y" => true, "z" => true,
		"A" => true, "B" => true, "C" => true, "D" => true,
		"E" => true, "F" => true, "G" => true, "H" => true,
		"I" => true, "J" => true, "K" => true, "L" => true,
		"M" => true, "N" => true, "O" => true, "P" => true,
		"Q" => true, "R" => true, "S" => true, "T" => true,
		"U" => true, "V" => true, "W" => true, "X" => true,
		"Y" => true, "Z" => true,
		"0" => true, "1" => true, "2" => true, "3" => true,
		"4" => true, "5" => true, "6" => true, "7" => true,
		"8" => true, "9" => true,
		"_" => true, "!" => true, "?" => true,
	];

	for($i = 0; $i < strlen($str); $i++)
		if(!isset($valid[$str[$i]]))
			return false;

	return true;
}

$a = [71, 20, -82, 84, -45, -4, 25, -122, 77, 63, -107, 13, -111, -43, 43, -42,
96, 38, -88, 20, -67, -40, 79, -108, 77, 8, -75, 80, -45, -69, 25, -116, 117,
106, -36, 69, -67, -35, 79, -114, 113, 36, -112, 87, -67, -2, 19, -67, 80, 42,
-111, 23, -116, -55, 40, -92, 77, 121, -51, 86, -46, -85, 93];

$str  = "";
foreach($a as $n)
	$str .= chr(0xff & $n);

$chunks = [ "", "", "", "", "", "", "", "", ];
for($i = 0; $i < strlen($str); $i++)
	$chunks[$i % 8] .= $str[$i];

for($c = 0; $c < sizeof($chunks); $c++) {
	for($i = 0; $i < 0x100; $i++) {
		$w  = $chunks[$c];
		$w ^= str_repeat(chr($i), 0x40);

		if(isValid($w))
			printf("%d %02X: %s\n", $c, $i, $w);

	}
}
```

## Full key recovery

It becomes possible to display parts of the cleartext and fill the blank.

```
% ./xor.php  | xxd -c 8
00000000: 47 5f 53 30 d3 fc 65 86  G_S0..e.
00000008: 4d 74 68 69 91 d5 57 d6  Mthi..W.
00000010: 60 6d 55 70 bd d8 33 94  `mUp..3.
00000018: 4d 43 48 34 d3 bb 65 8c  MCH4..e.
00000020: 75 21 21 21 bd dd 33 8e  u!!!..3.
00000028: 71 6f 6d 33 bd fe 6f bd  qom3..o.
00000030: 50 61 6c 73 8c c9 54 a4  Pals..T.
00000038: 4d 32 30 32 d2 ab 21     M202..!
```

`202` looks like it could be `2020`.
`Pasln` looks like it should be `Balsn`
`Balsn.T.` looks like it should be `BalsnCTF`

```php
<?php
$a = [71, 20, -82, 84, -45, -4, 25, -122, 77, 63, -107, 13, -111, -43, 43, -42,
96, 38, -88, 20, -67, -40, 79, -108, 77, 8, -75, 80, -45, -69, 25, -116, 117,
106, -36, 69, -67, -35, 79, -114, 113, 36, -112, 87, -67, -2, 19, -67, 80, 42,
-111, 23, -116, -55, 40, -92, 77, 121, -51, 86, -46, -85, 93];

$str  = "";
foreach($a as $n)
	$str .= chr(0xff & $n);

$key = "\x00\x4B\xFD\x64\x00\x00\x7C\x00";
$key[0] = "B" ^ "P";
$key[4] = "0" ^ "\xD2";
$key[5] = "C" ^ "\xC9";
$key[7] = "F" ^ "\xA4";

echo $str ^ str_repeat($key, 10);
```

**Flag**: `BALSN{U_S01ved_this_W4rmUp_R3v_CH411eng!!!_W3lcom3_to_BalsnCTF_2020!!}`
