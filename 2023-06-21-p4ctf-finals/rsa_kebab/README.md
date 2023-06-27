# RSA Kebab (crypto, 9 solves, 309p)

## Introduction

We get a classic RSA challenge.
Two 512 bit primes `p` and `q` are generated and flag is encrypted using 65537 and `p*q`.
The goal is to recover private key and decrypt the flag.

## Task analysis

The obvious strange step of the task is key generation:

```python
class Random:
    def __init__(self, seed: int | None = None):
        if seed is None:
            seed = int.from_bytes(os.urandom(32))
        self.seed = seed

    def next_below(self, limit: int) -> int:
        self.seed += 1
        return pow(3, self.seed, limit)

rng = Random()

def gen_prime(bits: int) -> int:
    p = rng.next_below(2**bits)
    while not isPrime(p):
        p = rng.next_below(2**bits)
    return p
```

One interesting point is that both primes are generated as `3^x mod 2**512`.
Second interesting thing is that rng state is not reset between primes generation, which means the random `seed` is the same, and that both primes are related.

Specifically if `p = 3^x mod 2**512` then `q = p*3^y mod 2**512 = 3^(x+y) mod 2**512`.

It's worth pointing out that `y` in this case is relatively small (in the order of hundreds).

This means that modulus `n = p*q = p * (p*3^y mod 2**512)`

## Solution

There are 2 ways to approach this task.
In both cases we would like to first simplify the modulus equation a bit.

We notice that if we take `n % 2**512` we can simplify the modulus to:

`n mod 2**512 = p * (p*3^y mod 2**512) mod 2**512 = p**2 * 3^y mod 2**512 = 3**(2x+y) mod 2**512`

### Modular root approach

As mentioned before, `y` is small and we can easily brute-force through all possible values.
This means we can multiply by `modinv(3^i, 2**512)` to "cancel out" this factor if we happen to match `y==i`.

We get `n * modinv(3^y, 2**512) mod 2**512 = p**2 mod 2**512`

Now we can simply take modular square root of this value to get back `p`.
Normally taking modular roots over composites require taking root mod each prime and then combining results via CRT.
Here we have a special case becase we have repeated primes in the modulus factorization and we need to use Hensel Lifting to raise solution mod `prime` to solution mod `prime^k`.

Simple implementation can be found at https://github.com/p4-team/crypto-commons/pull/18

We run:

```python
from Crypto.Util.number import isPrime, long_to_bytes

from crypto_commons.rsa.rsa_commons import modinv, modular_sqrt_composite_powers

orig_n = 13771684781863672921848566748720202957210603942122793837377840406546820242143725489540652846164899938861536496478520157404839773084308133557276555462188469715721933984828717376101108000101432855119452703510547117221794988719915407350144110893005954162971939914024994040271947897805274102956866800030093979441
n = orig_n
c = 6431362685573474637258810483327472270863448862704912756147838098490350521005551488774051556389731399561610146827473244205316244320957680948131569291105713461238294440397538795470655338633266133823822552348682452593348425580333815632588651366242819131705997677117725446144306897047883449077724369906480303118
for i in range(1000):
    n = (n * modinv(3, 2 ** 512)) % 2 ** 512
    res = modular_sqrt_composite_powers(n, [2] * 512)
    for x in res:
        if isPrime(x) and isPrime(orig_n // x):
            p = x
            q = orig_n // x
            d = modinv(65537, (p - 1) * (q - 1))
            print(long_to_bytes(pow(c, d, orig_n)))
```

To recover the flag: `p4{dedicated_to_the_kebab_place_in_Bielefeld_that_cryptographically_signs_their_kebabs_https://i.imgur.com/sDb0bxt.png}`

### Discrete log approach

If we look at the other form of the equation above we have:

`n mod 2**512 = 3**(2x+y) mod 2**512`

We can take discrete log of `n mod 2**512` to recover `2x+y`.
In general case discrete log is a hard problem, however here the modulus is a smooth integer, making this trivial.
Once we have `2x+y` we can again brute-force the value of `y` and check every potential `x` we get.
