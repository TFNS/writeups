# Dirty Laundry (crypto, 636p, 14 solved)

A fun crypto challenge. Realized that my solution was different from the one
already published on CTFtime, so decided to contribute a little.

We get the [challenge code](chall.py) and its [output](output.txt).
Essentially, a strong 1024-bit prime is generated, and used to seed a custom
prng. Then, a polynomial `ax^2 + bx + c` in GF(prime) is created, where `c` is
the flag. This polynomial is then evaluated for `x in [1..5]`. A noisy value
(generated using the custom PRNG) is added to this result, and the final
result is encrypted using the Paillier cryptosystem.

Here are the steps I followed to recover the flag.

## Breaking the PRNG

The PRNG implementation is

```python
class PRNG256(object):
    def __init__(self, seed):
        self.mask = (1 << 256) - 1
        self.seed = seed & self.mask

    def _pick(self):
        b = ((self.seed>>0)^(self.seed>>2)^(self.seed>>5)^(self.seed>>10)^1)&1
        self.seed = ((self.seed>>1)|(b<<255)) & self.mask
        return b

    def rand(self):
        x = 0
        for i in range(256):
            x = (x << 1) | self._pick()
        return x
```

Since the state is 256-bits long, and each `_pick` operation consumes 1 bit
from the state, the `rand` function consumes and resets one full state. It is
therefore quite trivial to retrieve the state at a given point in the
computation:

```python
# Given `out` an output of the PRNG, we reconstruct the PRNG as follows:
y = PRNG256(int(bin(out)[2:].zfill(256)[::-1], 2))
```

Once the state is retrieved, it's easy to reverse it as well to recover
previous output values:

```python
def reverse_state(self):
    seed = self.seed
    for _ in range(256):
        cur = (seed >> 255) & 1
        b0 = ((seed >> 1)^(seed >> 4)^(seed>>9)^cur^1)&1
        seed = ((seed << 1) | b0) & self.mask

    self.seed = seed
```

Now, given any public key `(n, g)` given for the Paillier encryption step, we
are able to retrieve one output of the PRNG by doing:

```python
out = (g - 1) / n
```

The reason this works is because `1 + prng.rand() * n` is systematically
smaller than `n^2`, as `prng.rand()` is 256 bits long, and `n` is 1536 bits
long.

So with this, we know all the values output by `prng.rand()` during the
encryption. Bonus: we know the low 256 bits of `PRIME`, as it is used to
originally seed the PRNG.

## Decrypting the Paillier encryption

```python
def paillier_enc(m, p, noise):
    p = next_prime(p + noise)
    q = getStrongPrime(512)
    n = p * q
    g = (1 + prng.rand() * n) % n**2
    c = pow(g, m, n**2) * pow(prng.rand(), n, n**2) % n**2
    return n, g, c
```

Since we know all the outputs of the PRNG as well as `n`, `g` and `c`, we can
now retrieve:

```python
pow(g, m, n**2) = c * pow(prng.rand(), n, n**2)**(-1) % n**2
```

Although this is an instance of the DLP, it has certain properties that allow
us to compute it easily (the Paillier cryptosystem actually relies on that).

The rule can be informally given as:

```python
(1 + n)**m = 1 + mn [n**2]
```

Since `g = 1 + k*n` for some prime `k`, we have that:

```python
g**m = (1 + k*n)**m = 1 + m*k*n [k**2n**2]
```

This is not exactly what we have here but `1 + m*k*n` is still smaller than
`n**2` since m is 1024 bits long and k is 256 bits long (1024 + 256 < 1536).
Thus, since `k**2n**2 % n**2 == 0`, we have that:

```python
g**m = 1 + m*k*n [n**2]
```

From that, it's trivial to recover `m`. Here is sample code:

```python
r = pow(rng.rand(), n, n**2)
m = (c * invert(r, n**2)) % n**2

assert (m - 1) % (g - 1) == 0

m = (m - 1) / (g - 1)
```

With that, we recovered the `m` parameter of the call to `pailler_enc`. To
retrieve the result of the polynomial evaluation, we just subtract the noise
value that was generated using the broken PRNG.

```python
m = m - noise
```

## Recovering PRIME

Doing the previous step, we can recover the evaluation of the polynomial in
five points, such that we have:

```python
prime = PRIME

m1 = m[0]
m2 = m[1]
m3 = m[2]
m4 = m[3]
m5 = m[4]

# x = 1, a    + b   + c = m1 [prime]
# x = 2, a*4  + b*2 + c = m2 [prime]
# x = 3, a*9  + b*3 + c = m3 [prime]
# x = 4, a*16 + b*4 + c = m4 [prime]
# x = 5, a*25 + b*5 + c = m5 [prime]
```

We are looking for some linear combinations `L`, such that on principle,
`L == 0`. However, if we find a case where `L` should be `0` and isn't, then
we have found a multiple of `PRIME`, most likely with low divisors if any. Good
candidates for this `L` would be `L = x - x` where `x` is represented by two
different values.

I found the following:

```python
# 2a  = 6a - 4a
a2p = (2 * m1 + m4 - 3 * m2) - (m4 - m3 - m2 + m1)

# 6a
a6p = (2 * m1 + m4 - 3 * m2)
# 8a
a8n = m5 - m3 - m3 + m1

# 2a = 8a - 6a
a2n = a8n - a6p

# YAY, it's the prime!
PRIME = a2p - a2n

# Bonus: possible to check that the value looks good.
assert PRIME % 2**256 == orig_rng.seed % 2**256
```

With `PRIME` known and the equations available, it is now trivial to recover
the flag:

```python
inv2 = invert(2, PRIME)

a = (a2p * inv2) % PRIME
b = (m2 - m1 - 3*a) % PRIME
c = (m1 - a - b) % PRIME

print(hex(c)[2:].replace('L', '').decode('hex'))
```

And we get: `zer0pts{excellent_w0rk!y0u_are_a_master_0f_crypt0!!!}`.

Complete solution [here](solve.py) and commented challenge file
[here](commented_chall.py)
