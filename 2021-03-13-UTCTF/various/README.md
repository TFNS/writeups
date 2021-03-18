# Various Venacular (beginner/crypto, 340p, 258 solved)

## Description

```
This flag was intercepted. wmysau{foeim_Tfusoli}

Unfortunately, it seems to be encrypted. Additional encrypted text was also found.
Hkgxologflutleiaymt xgf Azutgkrftmtf ltmntf ERW wfr ELW wfmtk Rkweq.
```


## Task analysis

It's pretty clear we're dealing with some substitution cipher with only a-zA-Z charset.
It's not monoalphabetic, so most likely Vigenere.


## Solution

We could try some cryptanalysis on the second, longer text, but there is a simpler way.
We can strip flag format and put this into https://quipqiup.com/ setting clue `wmysau=utflag` and this gives us:

`utflag nicht English`

We can similarly drop the text to get:

`Provisionsgeschafte von Amgeordneten setzen CDU und CSU unter Druck.`
