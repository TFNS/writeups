# Chunk Norris (crypto, 98p, 127 solved)

## Description

In the task we get [RSA-like code](challenge.py) and [output](output.txt).

## Code analysis

### Main

The `main` code is pretty short and simple:

1. Generate two 1024 bit primes
2. Combine them to form RSA modulus
3. Encrypt flag with e=65537

### Prime generation

The real deal in this task lies in the prime generation procedure.
If the primes were truly random, we would be facing a general RSA problem, and most likely would not be able to solve this.

However, in this case the prime generation procedure is a bit fishy.
Primes are generated using LCG with random seed, and known `a` and modulus:

```python
def gen_prime(bits):
  s = random.getrandbits(chunk_size)

  while True:
    s |= 0xc000000000000001
    p = 0
    for _ in range(bits // chunk_size):
      p = (p << chunk_size) + s
      s = a * s % 2**chunk_size
    if gmpy2.is_prime(p):
      return p
```

1. Generate random seed
2. Shift result by chunk_size
3. Add current seed to the result
4. Create new seed as `seed = a*seed%2**chunk_size`
5. Repeat steps 2-5 until we have enough bits

## Solution

We want to recover value of initial seed for one of the primes, and use it to re-generate this prime and thus break RSA modulus.

### Recover initial seeds product

We start off by recovering product of both initial seeds.

#### Recover top part of initial seeds product

Note that initial seed is being shifted to the left from the start, so it will end up as leftmost chunk of the prime.

So the prime have form: `SABCD` where `S` is initial seed, `A = S*a%2**chunk_size`, `B = S*a**2%2**chunk_size` etc.

This implies that if you multiply two such numbers, leftmost bits if the result will be top half bits of `S1*S2`.

For test purposes let's modify `gen_prime` so that it returns also the initial seed.
Then if we run:

```python
def sanity2():
    s, p = gen(256)
    w, q = gen(256)
    n = p * q
    bits = 256 * 2
    print(hex(n))
    top = (n - (n % 2 ** (bits - 64))) >> (bits - 64)
    print(hex(top))
    print(hex(s * w % 2 ** 128 >> 64))


sanity2()
```

We can confirm this is true.
So we can easily recover upper half of bits of two initial seeds by:

```python
def get_top(n, bits, chunk_size):
    top = (n - (n % 2 ** (bits * 2 - chunk_size))) >> (bits * 2 - chunk_size)
    return top
```

Note that sometimes we're unlucky and there is enough carry from lower bits, that they flip LSB we just recovered.
In most cases is just off-by-one.

#### Recover bottom part of initial seeds product

Now let's look at the other side of `n`, so low bits.
If we again refer to the prime format `SABCD`, lowest bits of two such primes multiplied have to be bottom half of bits of `D1*D2`.

But we also know that:
```
D1*D2 = S1*a**4%2**chunk_size * S2*a**4%2**chunk_size
D1*D2 = S1*S2 * a**8%2**chunk_size
```

So if we multiply this by `modinv(a**8, 2**chunk_size)` we will get `S1*S2 % 2**chunk_size`.
And those are bottom bits of `S1*S2`.

So we can do:

```python
def get_bottom(n, bits, chunk_size):
    a = 0xe64a5f84e2762be5
    bottom = (n % 2 ** chunk_size)
    bottom = (bottom * modinv(a, 2 ** chunk_size) ** ((bits / chunk_size - 1) * 2)) % 2 ** chunk_size
    return bottom
```

We can use this in a sanity check again:
```python
def sanity3():
    s, p = gen()
    w, q = gen()
    n = p * q
    print(hex(s * w % 2 ** 64))
    print(hex(get_bottom(n, 64 * 4, 64)))


sanity3()
```

#### Recover initial seeds product

We can now simply combine the above methods:

```python
def recover_components(n, bits, chunk_size):
    top = get_top(n, bits, chunk_size)
    bottom = get_bottom(n, bits, chunk_size)
    return (top << chunk_size) + bottom, ((top - 1) << chunk_size) + bottom
```

We return 2 values, to account for potential off-by-one in top part of the bits.

### Recover initial seeds from the product and factor N

Now that we know the product of initial seeds we want to split it.
The seed size is too large to brute-force this, but notice that there are not that many potential options here!
The idea is that the prime factors of the product we have, are also prime factors of both of the seeds.

This means we can factor the seeds product, and then check every possible selection of prime factors, and consider this as factorization of one of the seeds.

1. Test every set from powerset over `seeds product` factors
2. Multiply values in the current set, to get seed_candidate
3. Generate value based on given seed
4. If value is a prime, check if it divides `n`

```python
for factors_for_candidate in powerset(primes):
    seed_candidate = multiply(factors_for_candidate)
    p = gen_from_seed(seed_candidate, 1024, 64)
    if p is not None:
        print(hex(seed_candidate), p)
        q = n / p
        d = modinv(e, (p - 1) * (q - 1))
        print(rsa_printable(c, d, n))
```

Two potential `seeds products` we get for task inputs are `(227963529990382503519930590718284598961L, 227963529990382503501483846644575047345L)`

We get factors from factordb:

```
primes = [11, 61, 443, 21751, 1933727, 53523187, 340661278587863]
primes = [3, 5, 41, 43, 509, 787, 31601, 258737, 28110221, 93627982031]
```

And once we run the above loop we quickly get: `CTF{__donald_knuths_lcg_would_be_better_well_i_dont_think_s0__}`
