# Farmers only (misc/crypto, 990p, 34 solved)

## Description

```
My friend Ron is a grain farmer, and was going on and on about this messaging scheme he learned about that promises "confidentiality without encryption" (whatever that means). He gave me these files to try it out with and asked if I could "separate the wheat from the chaff". Shouldn't be too bad...

All numerical input to the HMAC should be treated as numbers, not strings. The message you will be HMACing is <bytes of sequence # || bytes of bit> where || is concatenation

Note: You must wrap the answer in utflag{} before submitting!
```

We also get DH params:

```
p = 78787
g = 16405

A = 59145
B = 18081
```

[And algorithm output](output.txt)


## Task analysis

The task is classsis example of https://en.wikipedia.org/wiki/Chaffing_and_winnowing
The idea is to recover the HMAC key and then calculate HMAC for given input, and compare it with two available signatures, to figure out which data are valid.

## Solution

### Key recovery

First step is to recover DH parameters.
This is trivial since numbers are so small.
We can use any discret log algorithm, like BS-GS:

```python
def baby_steps_giant_steps(a, b, p, N=None):
    if not N: N = 1 + int(math.sqrt(p))
    baby_steps = {}
    baby_step = 1
    for r in long_range(0, N + 1):
        baby_steps[baby_step] = r
        baby_step = baby_step * a % p
    giant_stride = gmpy2.powmod(a, (p - 2) * N, p)
    giant_step = b
    for q in long_range(0, N ** 8 + 1):
        if giant_step in baby_steps:
            result = q * N + baby_steps[giant_step]
            return result
        else:
            giant_step = giant_step * giant_stride % p
```

And do:

```python
    p = 78787
    g = 16405
    A = 59145
    B = 18081
    a = baby_steps_giant_steps(g, A, p)
    b = baby_steps_giant_steps(g, B, p)
    shared = pow(g, a * b, p)
    print(shared)
```

To get: `76780`

### Chaffing and winnowing

Now we simply need to iterate over the data, calculate HMAC and check for which bit the hash matches:

```python
    res = {}
    for seq, bit, digest in data:
        hm = hmac.new(long_to_bytes(shared), long_to_bytes(seq) + long_to_bytes(bit), digestmod=hashlib.md5).hexdigest()
        if hm == digest:
            res[seq] = bit
    real_res = ''
    for i in range(0, 183):
        real_res += str(res[i])
    print(''.join([chr(int(c, 2)) for c in chunk_with_remainder(real_res, 8)]))
```

And we get `cream_of_the_crop_2907`
