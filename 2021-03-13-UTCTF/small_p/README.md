# Small p problems (crypto, 420p, 242 solved)

## Description

```
My buddies Whitfield and Martin were trying to share a secret key between themselves, and I was able to eavesdrop on their conversation. I bet I could probably figure out their shared secret with a little math...

p = 69691
g = 1001

A = 17016
B = 47643

Note: submit either the shared secret or the shared secret wrapped in utflag{}
```

## Task analysis

It seems we just have parameters of DH exchange with very small values.

## Solution

Similarly to first part of `Farmers only` we can simply calculate discrete logarithm, eg. with BS-GS, and then calculate shared secret.

```python
def baby_steps_giant_steps(a, b, p, N=None):
    if not N: N = 1 + int(math.sqrt(p))
    baby_steps = {}
    baby_step = 1
    for r in long_range(0, N + 1):
        baby_steps[baby_step] = r
        baby_step = baby_step * a % p
    giant_stride = pow(a, (p - 2) * N, p)
    giant_step = b
    for q in long_range(0, N ** 8 + 1):
        if giant_step in baby_steps:
            result = q * N + baby_steps[giant_step]
            return result
        else:
            giant_step = giant_step * giant_stride % p


def main():
    p = 69691
    g = 1001
    A = 17016
    B = 47643
    a = baby_steps_giant_steps(g, A, p)
    b = baby_steps_giant_steps(g, B, p)
    print(pow(g, a * b, p))
```

And we get `53919`
