# Accessible Sesamum Indicum - IrisCTF 2024 (crypto, 133 solved, 50p)

## Introduction
Accessible Sesamum Indicum is a cryptography task.

A Python script simulating vaults with a 4-digit PIN codes is given.

## Analysis
The script simulates a vault with an hexadecimal keypad. Trying every pins
(0000, 0001, 0002, etc.) will require pressing 4 × 16⁴ keys. This is 4 times
above the limit of 65536 keys.

Opening multiple connections to the remote server until the randomly-selected
PIN is in the lower quarter will not work, because there are 16 vaults to solve.
The probability of succeeding 16 times in a row is (1/4)¹⁶ ≃ 2e-10.

## Exploitation
This problem can be solved with a [de Bruijn sequence](https://en.wikipedia.org/wiki/De_bruijn_sequence)

**Flag**: `irisctf{de_bru1jn_s3quenc3s_c4n_mass1vely_sp33d_up_bru7e_t1me_f0r_p1ns}`

## Appendices
### solve.py
```python
import pwn

db = pwn.de_bruijn("0123456789abcdef", 16)
for i in range(16):
	print(db)
```
