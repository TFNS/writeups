# Dead drop 1 (crypto, 169p, 24 solved)
# Dead drop 2 (crypto, 217p, 17 solved)


We put both tasks in a single writeup because attack we used breaks both challenges and there is pretty much no difference between them from our point of view.
This suggests it might be an unintended vector...

## Description

In the task we get sources [one](dead_drop_1.py) and [two](dead_drop_2.py) and also corresponding encrypted flags [one](flag1.enc) and [two](flag2.enc).

In the task we are facing `Naccache Stern Knapsack (NSK) cryptosystem`:

```python
from Crypto.Util.number import *
import random
from flag import flag

p = 22883778425835100065427559392880895775739

flag_b = bin(bytes_to_long(flag))[2:]
l = len(flag_b)

enc = []
for _ in range(l):
	a = [random.randint(1, p - 1) for _ in range(l)]
	a_s = 1
	for i in range(l):
		a_s = a_s * a[i] ** int(flag_b[i]) % p
	enc.append([a, a_s])

f = open('flag.enc', 'w')
f.write(str(p) + '\n' + str(enc))
f.close()
```

The difference between tasks is just that `p` in version 1 is a composite and in version 2 it's a prime.
Apart from that in version 2 we get more data points.

The idea of the algorithm is that random values `a[i]` are either included in the product or not, depending on whether `i-th` secret bit is `1` or `0`.

So for example if bits as `1001` then product is `a[0]*a[3]` because bits corresponding to `a[1]` and `a[2]` are 0.

Of course if this product was not reduced `mod p` we could easily calculate `gcd(a[i],a_s)` to know if `a[i]` was part of the product.
But modular reduction breaks this property.

We know the flag prefix and suffix, so we could `fix` some bits.
Also in `v1` we could fix some `0` bits by inspecting:

```python
if gcd(a[bit_number], p) != 1 and gcd(gcd(a[bit_number], p), a_s) == 1:
    bits[bit_number] = 0
```

but this is not enough.

## Solution

We stumbled at the solution when reading the paper introducing this cryptosystem: `Naccache, David, and Jacques Stern. "A new public-key cryptosystem." International Conference on the Theory and Applications of Cryptographic Techniques. Springer, Berlin, Heidelberg, 1997.` https://www.di.ens.fr/~stern/data/St63.pdf

At point `2.4` authors mention an interesting property of this cryptosystem.
It seems that due to multiplicative property of Legendre symbol it's possible to leak parity of the secret bits.
Then authors suggest that this is not serious, unless in special case when attacker has multiple encryptions of the same message...

We basically want to use the fact that `legendre(a_s,p) == legendre(a[i],p) * legendre(a[m],p) * ... * legendre(a[k],p)` where `i,m,...,k` are indices where bit is 1.

Now we want to express the above property in terms of sum in `GF(2)`, so we can make this into a matrix equation.
We basically change the multiplication into addition mod 2.

Since legendre symbol returns `-1` or `1` (unlikely to get a `0`) we make a transposition of this by doing `+2 mod 3`.
This way `-1` becomes `1` and `1` becomes `0`.

Notice that now the `Legendre` property stated above still holds, but now we're just doing additions!
For example:

```
-1 * 1 * 1 = -1
```

Is now:

```
1 + 0 + 0 mod 2 = 1
```

Solution so this matrix will be a bitvector stating which of the terms `1` and `-1` need to be included for this property to hold.

### V1

The only particular thing we need to do here for `v1` is that `p` is not prime so we can't do `legendre(a_s,p)`, and we need to use one of prime factors as modulus.
The bigger the better, because it's lower chance of actually getting `legendre` to return a `0`.

The solution is:

```python
def legendre_GF2(x, mod):
    assert kronecker(x, mod) != 0
    return (kronecker(x, mod) + 2) % 3

def solve(mod, enc, flag):
    matrix_eq  = []
    vector_res = []

    for a, a_s in enc:
        a_s = legendre_GF2(a_s % mod, mod)
        a   = [legendre_GF2(x % mod, mod) for x in a]
        
        vector_res.append(a_s)
        matrix_eq.append(a)

    for i in range(len(flag)):
        if flag[i] == None:
            continue
        new_eq    = [0] * len(flag)
        new_eq[i] = 1

        matrix_eq.append(new_eq)
        vector_res.append(flag[i])

    A = Matrix(GF(2), matrix_eq)
    B = vector(GF(2), vector_res)

    res = A.solve_right(B)

    res_string = ''
    for c in res:
        res_string += str(c)

    return long_to_bytes(int(res_string, 2))
```

Now it might be that some of the vectors in our matrix are not independent, so we include here `flag` wich is array with bits we know from the flag format.

We call this via:

```python
def main():
    with open('flag1.enc', 'rb') as f:
        p = int(f.readline().strip())
        enc = eval(f.readline())
        # Factorisation of p is 19 * 113 * 2657 * 6823 * 587934254364063975369377416367
        mod = 587934254364063975369377416367
    
        flag = [None] * len(enc)
        start = bin(bytes_to_long(b'ASIS{'))[2:]
        end   = bin(bytes_to_long(b'}'))[2:].zfill(8)
        # We know the end of the flag
        for i in range(len(start)):
            flag[i] = int(start[i])
        # We know the start of the flag
        for i in range(-1, -len(end) - 1, -1):
            flag[i] = int(end[i])

        result = solve(mod, enc, flag)
        print(result)

main()
```

And we get `ASIS{175_Lik3_Multivariabl3_LiNe4r_3QuA7i0n5}`

### V2

It should be pretty clear now, that this solution really doesn't change at all with respect to `v2` of the task.
There is no flag format, so we can't use that, but we have more inputs to work with, so most likely we will have just enough independent vectors.
We run:

```python

def main():
    with open('flag2.enc', 'rb') as f:
        p = mod = int(f.readline().strip())
        enc = eval(f.readline())
        flag = [None] * len(enc)
        result = solve(mod, enc, flag)
        print('ASIS{'+result+'}')

main()
```

with the same solver code and we get `ASIS{Z_q_iZ_n0T_a_DDH_h4rD_9r0uP}`

Complete solver [here](solver.sage)
