# dhash - IrisCTF 2024 (crypto, 98 solved, 68p)

## Introduction
dhash is a cryptography task.

A Python script implementing a hash function is given.

## Analysis
The hash function implemented in this challenge is similar to the RSA
cryptosystem: the script defines `n` to be `65537`, a common RSA exponent and
then generates a 2048-bits prime number `N`.

The script reads data from the user and split it in blocks of 256 bytes (2048
bits). Each block is hashed individually with `pow(data, e, N)` and every blocks
are then xorred with one another.

The flag is printed if an input that hashes to 0 is provided.

There are some checks on the input: it must not have partial blocks, and it
must have at least one block.

Each block can only be seen once (otherwise sending the same block twice would
xor it down to 0). On top of that, individual blocks must be in the range
`[2, N - 2]`

## Exploitation
`N` is a prime number (and not a composite), the private exponent d can be found
with `d = pow(e, -1, N - 1)`.

Let `x = 2`, `y = 4`, `z = 6`

and

`a = pow(x, d, N)`, `b = pow(y, d, N)`, `c = pow(z, d, N)`.

Hashing the three blocks `a`, `b`, `c` will return:

```
h = hash(a || b || c)
  = hash(a) ^ hash(b) ^ hash(c)
  = pow(a, e, n) ^ pow(b, e, n) ^ pow(c, e, n)
  = x ^ y ^ z
```

Since `x`, `y` and `z` have been chosen so that `x ^ y ^ z == 0`, then `h` will
also be 0.

**Flag**: `irisctf{no_order_factorization_no_problem}`

## Appendices
### pwn.py
```python
N = 28407292181163362182824063483022373554193916630580089129120517171191461718147627539812280200938963508536747258073949068887283505783411635265231165386702738986709796531429616425213887474353779437831263523011235073757554668126380494755109361697183465932405582927116047354089585761251510575761174818746292034117889764440776329200108236647973522695701548781384995126491092666796160869136187488249191390027367929428806249672719880115411073498878129185365966371957208267484085689357031947550901914696699086354554760410172783222362173920094064893030758974323750801662414072690420721467954275167877272830395923825851883693729
e = 65537

d = pow(e, -1, N - 1)
assert(1337 == pow(pow(1337, e, N), d, N))

a = pow(2, d, N)
b = pow(4, d, N)
c = pow(6, d, N)

s = f"{a:512x}" + f"{b:512x}" + f"{c:512x}"
print(s)
```
