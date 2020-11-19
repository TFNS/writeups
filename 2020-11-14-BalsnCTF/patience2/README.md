# Show your Patience and Intelligence II - Balsn CTF 2020 (misc, 380p, 24 solved)
## Introduction

The challenge contains a "VCD" file. It appears to be the output of an
oscilloscope.

This file contains a header that instructs the target has 4 wires :
```
$timescale 1 ns $end
$scope module top $end
$var wire 1 ! Channel_0 $end
$var wire 1 " Channel_1 $end
$var wire 1 # Channel_7 $end
$var wire 1 $ Channel_8 $end
$upscope $end
$enddefinitions $end
```

Then the files contains a lot of lines similar to these lines :
```
#292797800
0"
#292813600
1"
#292817000
0"
#292826600
1"
```

## Analysis

Presumably, the oscilloscope probes 4 wires (labelled `!`, `"`, `#` and `$`)
The `#123456` lines are timestamps while the `0"` lines are whether a wire sends
a signal or not.

The datasheets of the `MAX7219 LED dot matrix` are freely available on the
Internet.

It instructs us :
- it is possible to daisy-chain multiple displays (as seen on challenge I's
  video)
- the displays implement a serial protocol where each packet is 16 bits
- the address to register mapping

By using some unix magic, it is possible to make educated guesses regarding the
usage of bits :

```
% grep -P '^[01].' f3dae410dfe38c3fbf49aae3bf8b2f595ed05fde448bc4eec66aeb1bf99e5423.vcd |sort | uniq -c
    350 0!    350 1!
 179071 0" 179071 1"
      1 0#
  17156 0$  17156 1$
```

Wire `"` has the most changes. It must be the clock.
Wire `$` has a lot of changes too, it must carry data.

By fiddling with the input for a while, it is possible to recreate the output of
the displays.

**Flag**: `BALSN{I_spent_a_lot_of_time_drawing_letters_QAQ}`

## Appendices
### parse.php

```php
#!/usr/bin/php
<?php
$map = [
	'!' => "a",
	'"' => "b",
	'#' => "c",
	'$' => "d",
];

$regs = [];
$regs[0x00] = "no-op";
$regs[0x01] = "d0";
$regs[0x02] = "d1";
$regs[0x03] = "d2";
$regs[0x04] = "d3";
$regs[0x05] = "d4";
$regs[0x06] = "d5";
$regs[0x07] = "d6";
$regs[0x08] = "d7";
$regs[0x09] = "decode mode";
$regs[0x0A] = "intensity";
$regs[0x0B] = "scan limit";
$regs[0x0C] = "shutdown";
$regs[0x0F] = "display test";

$a = $b = $c = $d = null; // null so we can set the first batch to anything
$count  = 0;
$buffer = 0;

$digits = [];
$cur = 0;

while($line = trim(fgets(STDIN))) {
	if("$" === $line[0])
		continue;

	if("#" === $line[0]) {
		if($b === true) {
			$buffer <<= 1;
			$buffer  |= $d;

			$count++;
			if($count === 16) {
				$data = 0xFF & ($buffer >> 0);
				$addr = 0x0F & ($buffer >> 8);
				$rest = 0x0F & ($buffer >> 12);

				$count  = 0;
				$buffer = 0;

				// skip shutdown
				if($addr === 0x0C)
					break;

				// noop
				if($addr === 0)
					continue;

				// push into the digit array
				$idx = ($addr - 1) % 8;
				while($idx !== $cur) {
					$digits[] = 0;
					$cur = ($cur + 1) % 8;
				}
				$digits[] = $data;
			}
		}
		continue;
	}

	assert(2 === strlen($line));

	$var  = $map[$line[1]];
	$bool = "1" === $line[0];

	// We only toggle bits
	assert($$var !== $bool);
	$$var = $bool;
}

/* Display the $digits matrix */
for($i = 0; $i < 8; $i++) {
	foreach($digits as $dig) {
		if($dig & (1 << $i))
			printf("#");
		else
			printf(" ");
	}
	printf("\n");
}
```
