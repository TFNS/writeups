# Crazy (crypto, 154p, 27 solved)

## Description

In the task we get [source code](crazy.py) and [outputs](output.txt).

The challenge encrypt the flag using mutliple different keys.
Public keys we get are large composite numbers.

The encryption process splits the input into bits, chunks them to the size according with the public keyb bitsize (eg. keys of `2048` bits yield chunk of size `11` since `2^11 = 2048`).

Each input bitchunk is then xored with generated keystream.
Keystream generation starts with random `s_0` and first keystream block is `s_1 = r^2 mod n`, and each consecutive block is `s_i+1 = s_i^2 mod n`, all block cut to the chunk size.
Each keystream block is also `AND`ed with a random `xorkey` variable, constant for given public key.

The result we get is the combined encrypted bitstream and `s_last^2 mod n`.

## Vulnerabilities

### Prime reuse

First vulnerability in the task is the prime reuse in the public keys.
We can do pairwise `gcd` of the public keys to recover shared primes, and thus factor all the keys:

```python
def common_factor_factorization(ns):
    from itertools import combinations
    return [(n1, n2, gcd(n1, n2)) for n1, n2 in combinations(ns, 2) if gcd(n1, n2) != 1]
```

### Modular square root

Modular sqrt is a difficult problem, but only for composite moduli where you don't know the factors.
Otherwise it can be efficiently solved, see: https://github.com/p4-team/crypto-commons/blob/master/crypto_commons/rsa/rsa_commons.py#L272

This means that we can take the last `s_last^2 mod n` and recover `s_last` from that.
And we can do that `k` times to recover all `s_i` values used as keystream.
The only issue is that modular sqrt returns multiple potential candiates, so on each level we could have more and more candidates.
Fortunately organizers were gracious and each level has only 4 distinctive values for `s_i`.

We can get the `s_i` values as:

```python
def calculate_si(si2, p, q, levels):
    result = []
    potential = [si2]
    for i in range(levels):
        roots_on_level = []
        for x in potential:
            try:
                roots = modular_sqrt_composite(x, [p, q])
                roots_on_level.extend(roots)
            except:
                pass
        potential = set(roots_on_level)
        result.append(set(roots_on_level))
    return result
```

We can make a simple sanity check to verify this:

```python
def sanity2():
    p = getPrime(256)
    q = getPrime(256)
    levels = 5
    initial_si = 123
    si = initial_si
    for i in range(levels):
        si = pow(si, 2, p * q)
    res = calculate_si(si, p, q, levels)
    for lev in res:
        print(len(lev))
    assert initial_si in res[-1]
```

### The same message encrypted under different public keys

We're still left with 2 potential issues here:

1. We don't know the `xorkey` value used for encryption for any of the keys. We could brute-force it, but it's 2^11 options to check...
2. Since each `s_i` has 4 candiates, we will get 4 potential plaintext for each block.

What is helpful is that we can perform this on each of the inputs we have, and we can then cross-check resulting potential blocks.
The trick is that the `real` block has to be present in all result sets, so hopefully we can find it by intersecting all the sets.

## Solution

We follow the ideas mentioned above:

1. Factor all the keys
2. For each key generate `s_i` values used in decryption
3. Brute-force `xorkey` value for each key
4. Decrypt the ciphertext under given `xorkey` and recover list of potential decryptions for each of the blocks
5. For given key create list of sets with all potential decryptions for each of the blocks
6. Intersect sets for each block from all the public keys
7. For every possible 

### Decryption function

Apart from `calculate_si` shown above we need an actual decrypt, but this is pretty simple, we just slighly modify the encrypt:

```python
def pad(val, h):
    if len(val) % h == 0:
        return val
    missing = h - len(val) % h
    return '0' * missing + val

def decrypt(enc, sis, p, q, xorkey):
    final = []
    pubkey = p * q
    h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1
    enc = pad(bin(enc)[2:], h)
    C = chunk(enc, h)[::-1]
    for i in range(len(C)):
        result = []
        for potential_s_i in sis[i]:
            k = bin(potential_s_i)[2:][-h:]
            c = bin(int(C[i], 2) ^ int(k, 2) & xorkey)[2:].zfill(h)
            result.append(c)
        final.append(set(result))
    return final[::-1]
```

We can make a simple sanity check to prove this works:

```python
def sanity():
    p = getPrime(1024)
    q = getPrime(1024)
    pubkey = p * q
    xorkey = 0x1f
    enc, si = encrypt("ABC", pubkey, xorkey)
    print(len(bin(enc)))

    h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1
    C = chunk(pad(bin(enc)[2:], h), h)[::-1]
    sis = calculate_si(si, p, q, len(C))
    decrypted = decrypt(enc, sis, p, q, xorkey)
    results = [long_to_bytes(int("".join(b), 2)) for b in itertools.product(*decrypted)]
    assert "ABC" in results
```

### Parallel solver

This is going to take some computations so let's make a nice independent function we can run in multiprocessor pool:

```python
def worker(data):
    p, q, enc, si = data
    pubkey = p * q
    h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1
    C = chunk(pad(bin(enc)[2:], h), h)[::-1]
    sis = calculate_si(si, p, q, len(C))
    results = defaultdict(set)
    for xor in range(0, 2 ** h):
        decrypted = decrypt(enc, sis, p, q, xor)
        for i, block in enumerate(decrypted):
            results[i].update(block)
    return results
```

For given key this will generate `s_i`, test every possible `xorkey` and generate list of sets with potential plaintext blocks.

Note that we want to use only data with the same `h` value, so we need to check:

```python
h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1
```

and choose for example only `h=11` keys.
This is because the blocks get split differently otherwise!

Now we can just do on PyPy:

```python
from crypto_commons.brute.brute import brute

results = brute(worker, dataset, processes=6) # as many cores as you have -2 just so you don't kill yourself...
blocks = len(results[0])
commons = []
for block in range(blocks):
    common = set.intersection(*[r[block] for r in results])
    print(block, common)
    commons.append(common)
for b in itertools.product(*commons):
    bits = "".join(b)
    flag = long_to_bytes(int(bits, 2))
    if 'ASIS{' in flag:
        print(flag)
```

And wait a bit...

After a moment we get a single match for the flag: `ASIS{1N_h0nOr_oF__Lenore__C4r0l_Blum}`
