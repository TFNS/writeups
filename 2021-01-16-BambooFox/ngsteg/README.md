# NGSteg - BambooFox CTF 2021 (misc, 500p)

## Introduction
NGSteg is a steganography task.

An archive containing a music, its beat map for the K-Shoot MANIA game and an
album jacket are provided.

The README file explicitely states that the flag is hidden in the `grv.ksh`
file.

This file is a text file that represents the objects and effects of a song.

## Hint
A hint has been released for this challenge. The hint made it clear that it is
mandatory to use K-Shoot MANIA instead of Unnamed SDVX Clone. The game can only
be run on Windows, the interface is in Japanese, and the characters were
displayed as [mojibakes](https://en.wikipedia.org/wiki/Mojibake)

The hint also insisted on the "Next Generation" idea by claiming that they
converted the chart to the latest version because it was too easy.

The
[KSH Chart File Format Specification](https://github.com/m4saka/ksh/blob/master/ksh_format.md)
mentions that there exists several revisions of the file format.

One particular difference is that previous charts used to represent effects with
a single letter:
> Legacy KSH charts (before v1.60) use these characters for a long FX note:
> - "S": Retrigger;8
> - "V": Retrigger;12
> - "T": Retrigger;16
> - "W": Retrigger;24
> - "U": Retrigger;32
> - "G": Gate;4
> - "H": Gate;8
> - "K": Gate;12
> - "I": Gate;16
> - "L": Gate;24
> - "J": Gate;32
> - "F": Flanger
> - "P": PitchShift
> - "B": BitCrusher
> - "Q": Phaser
> - "X": Wobble;12
> - "A": TapeStop
> - "D": SideChain

The flag is encoded as effects in the song using the 1.60 effects

```
% fgrep fx- grv.ksh | php pwn.php
[...]
fx-l=F
fx-r=L
fx-l=A;50
fx-r=G
fx-l=I
fx-r=S
fx-l=I
fx-r=B;10
fx-r=Q
fx-l=D
fx-r=A;50
fx-l=I
fx-r=X
fx-l=J
fx-r=F
fx-l=B;10
fx-l=X
fx-r=S
fx-r=D
fx-l=J
fx-r=B;10
[...]
```

The flag does not appear to have any logic. (Bopomofo keyboard perhaps?)

**Flag**: `flag{IBQDAIXJFBXSDJB}`

## Appendices
### pwn.php
```php
<?php
$from = [
	"Retrigger;8"   => "S",
	"Retrigger;12"  => "V",
	"Retrigger;16"  => "T",
	"Retrigger;24"  => "W",
	"Retrigger;32"  => "U",
	"Gate;4"        => "G",
	"Gate;8"        => "H",
	"Gate;12"       => "K",
	"Gate;16"       => "I",
	"Gate;24"       => "L",
	"Gate;32"       => "J",
	"Flanger"       => "F",
	"PitchShift"    => "P",
	"BitCrusher"    => "B",
	"Phaser"        => "Q",
	"Wobble;12"     => "X",
	"TapeStop"      => "A",
	"SideChain"     => "D",
];

$f = file_get_contents("php://stdin");
echo str_replace(array_keys($from), array_values($from), $f);
```
