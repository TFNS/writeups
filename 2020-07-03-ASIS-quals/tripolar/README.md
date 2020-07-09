# Tripolar (crypto, 159p, 26 solved)

## Description

As with most crypto challenges we get [source code](tripolar.py) and [encrypted flag](flag.enc)
The encryption code is pretty short:

```python
def crow(x, y, z):
	return (x**3 + 3*(x + 2)*y**2 + y**3 + 3*(x + y + 1)*z**2 + z**3 + 6*x**2 + (3*x**2 + 12*x + 5)*y + (3*x**2 + 6*(x + 1)*y + 3*y**2 + 6*x + 2)*z + 11*x) // 6

def keygen(nbit):
	p, q, r = [getPrime(nbit) for _ in range(3)]
	pk = crow(p, q, r)
	return (p, q, r, pk)

def encrypt(msg, key):
	p, q, r, pk = key
	_msg = bytes_to_long(msg)
	assert _msg < p * q * r
	_hash = bytes_to_long(sha1(msg).digest())
	_enc = pow(_msg, 31337, p * q * r)
	return crow(_enc * pk, pk * _hash, _hash * _enc) 
```

First multiprime RSA with 3 primes is generated and special public key value `pk = crow(p,q,r)` is calculated.
Then the flag gets encrypted via RSA with `e=31337` and modulus `n=p*q*r`.
Finally the encrypted flag, original message hash and public key are passed again via `crow`

## Solution

Judging by the flag, this is not the expected solution.
We used no special theorems, just very trivial high-school level math.

### Recover (x+y+z) value

We start off by noticing that `crow` polynomial contains fully `(x+y+z)^3`, and if we fold it, there are no other terms of such high order.
This is interesting because it means if we take 3rd integer root of the result of this function (multiplied by 6), we will get a very good approximation for `x+y+z`, because the root and integer cutoff will take care of all low order terms.

In fact this approximation turns out to be off by one, so we just recovered `x+y+z`!

```python
p, q, r = getPrime(256), getPrime(256), getPrime(256)
enc = crow(p, q, r)
root = gmpy2.iroot(enc * 6, 3)[0] - 1
assert root == (p + q + r)
```

### Recove x,y,z

#### Drop y from equation

We start with assumption that we have `enc = crow(x,y,z)`.
We already shown that we get recover `x+y+z` and thus we can do `r1 = enc - (x+y+z)**3` to drop this term from polynomial.

Since folding of the polynomial worked so well for order 3 we try to continue the same path, and remove `(x+y+z)^2`.
This is not as trivial, since some terms are not present, but we can of course do a classic `+1 -1` trick to get over this.

Lets mark `r2 = 6*(x+y+z)**2 - r1` (flip to simplify signs)

The polynomial part will be:

```
r2 = 6*(x+y+z)**2 - [x**3 + 3*(x + 2)*y**2 + y**3 + 3*(x + y + 1)*z**2 + z**3 + 6*x**2 + (3*x**2 + 12*x + 5)*y + (3*x**2 + 6*(x + 1)*y + 3*y**2 + 6*x + 2)*z + 11*x] - (x+y+z)**3

r2 = 6 * x * z + 6 * y * z + 3 * z + 3 * z ** 2 - 6 * x - 5 * (x+y+z)
```

Now we can do:

```
r2 + 5*(x+y+z) = z * (6 * y + 6 * x + 3 * z + 3) - 6 * x
```

Notice that we can extract `(x+y+z)` in the parenthesis still, getting to:

```
r2 + 5 * (x+y+z) = 3 * z * (2 * (x+y+z) + 1) - 3 * z ** 2 - 6 * x
```

Notice that left hand side is known, and on the right side we have only `z` and `x` because `x+y+z` is known!
We went from 3 variables to only 2!

#### Drop x from equation

Now it's time to follow my childhood idol and `go even further beyond!` (see https://www.youtube.com/watch?v=8TGalu36BHA )

Let's mark `S = x+y+z` and `L = r2 + 5 * S`

We have:

```
L = 3*z*(2*S+1) -3*z**2 - 6*x
```

Now if we divide this by `(2*S+1)` we get:

```
L/(2*S+1) = 3*z - 3*z**2/(2*S+1) - 6*x/(2*S+1)
```

Let's look for a moment at `6*x/(2*S+1)`.
Note that `S = x+y+z` and therefore `6*x/(2*S+1)` has to be very small!
It has to be smaller than `6x/2*x+1` because this is the upper bound when `y=z=0` (and we know it's not the case).

It can only be `0-3`, nothing more.
In reality it's not going to be `3` and the most likely value seems to be `2`.
Let's mark it as some `C`.
We can simply brute-force those values if needed to.
We have now:

```
L/(2*S+1) = 3*z - 3*z**2/(2*S+1) - C
L/(2*S+1) + C = 3*z - 3*z**2/(2*S+1)
3/(2*S+1) * z**2 - 3*z + L/(2*S+1) + C = 0
```

We effectively dropped `x` from the equation, and we're left with a simple quadratic equation!

#### Calculate z

Now we can simply solve this equation to recover value of `z`:

```python
RR = RealField(2000)
R.<v> = PolynomialRing(RR)
pol = (3*v**2)/(2*S+1) - 3 * v + L/(2*S+1) + 2 
for approx_z, _ in pol.roots():
  approx_z = int(approx_z)
  print(approx_z)
```

#### Calculate x

Now that we have `z` we can go back to our equation before we dropped `x`:

```
L = 3*z*(2*S+1) -3*z**2 - 6*x
6*x = 3*z*(2*S+1) -3*z**2 - L
x = (3*z*(2*S+1) -3*z**2 - L)/6
```

This this way we can recover `x`

#### Calculate y

Now that we have both `x` and `z` we can just use the fact that `S = x+y+z` and get `y = S - x - z`

#### Solver

Complete solver is just:

```python
def solve(enc, mode=2, gcd_bit_bound=700):
    S = ZZ(enc * 6).nth_root(3,truncate_mode=1)[0] - 1
    r1 = 6 * enc - (S) ** 3
    r2 = 6 * S ** 2 - r1
    L = r2 + 5 * S
    RR = RealField(2000)
    R.<v> = PolynomialRing(RR)
    pol = (3*v**2)/(2*S+1) - 3 * v + L/(2*S+1) +2
    for approx_z, _ in pol.roots():
        approx_z = int(approx_z)
        for c in range(-50, 50):
            cand_z = approx_z + c
            cand_x = int((3 * cand_z * (2 * S + 1) - 3 * cand_z ** 2 - r2 - 5 * S) // 6)
            cand_y = S - cand_z - cand_x
            enc = gcd(cand_x, cand_y)
            if mode == 1 and len(bin(enc)) > gcd_bit_bound or mode == 2 and is_prime(cand_x) and is_prime(cand_y) and is_prime(cand_z): 
                return cand_x, cand_y, cand_z
```

For smaller examples we could get just one exact root, but for larger data the roots are a bit "off" so we brute-force them a bit, and then verify if we got reasonable solution either by looking at bitsize or whether we have primes.

#### Sanity check

We can verify our logic by simple:

```python
def sanity():
    key = keygen(256)
    p, q, r, pk = key
    S = ZZ(pk * 6).nth_root(3,truncate_mode=1)[0] - 1
    assert S == (p + q + r)
    r1 = 6 * pk - (p + q + r) ** 3
    r2 = 6 * S ** 2 - r1
    x, y, z = p, q, r
    assert r2 == -(6 * (2 * x + y + z) - 6 * (x * z + y * z) - (x + y + 4 * z + 3 * z ** 2))
    assert r2 == 6 * (x * z + y * z) + (x + y + 4 * z + 3 * z ** 2) - 6 * (2 * x + y + z)
    assert r2 == 6 * (x * z + y * z) + (S + 3 * z + 3 * z ** 2) - 6 * (x + S)
    assert r2 == 6 * x * z + 6 * y * z + S + 3 * z + 3 * z ** 2 - 6 * x + -6 * S
    assert r2 == 6 * x * z + 6 * y * z + 3 * z + 3 * z ** 2 - 6 * x - 5 * S
    assert r2 + 5 * S == 6 * x * z + 6 * y * z + 3 * z + 3 * z ** 2 - 6 * x
    L = r2 + 5 * S
    assert L == z * (6 * y + 6 * x + 3 * z + 3) - 6 * x
    assert L == 3*z*(2*S+1) -3*z**2 - 6*x
    assert L/(2*S+1) == 3*z -3/(2*S+1)*z**2 - 6*x/(2*S+1)
    assert 3/(2*S+1)*z**2 - 3*z + L/(2*S+1) + 6*x/(2*S+1) == 0
    cand_x, cand_y, cand_z = solve(pk)
    assert z == cand_z
    assert x == cand_x
    assert y == cand_y
```

### Decrypt the flag

#### Recover enc, hash and pk

We can use our solver on the `enc` value we're given in the task, to recover the values passed to the `crow` function at the end of the encryption process.

Then we can calculate `gcd` between those values to `split` them, and extract `enc` and `pk`.
Then we run solver on `pk` to get back `p,q,r` and decrypt RSA:

```python
def main():
    res = 2149746514930580893244331421788929339625440444035620415342330419606266919679366683714353190036245926925599992281979981146349624735527272311371385020589871836913619378311391262773292002172286277050453912686346788369011436136749187588094689078604688584902911179760648455086471764073748888909794220109293997848416687601544131530407244078221642967646447253616998155897027002613854305998810584288668106945154515431677901508248501719233358613388284911544653423679952387626753952473637341066170188791146059852636168715040552123771116865138447219250612402255341219117297714079726770332109952708459351802562275694535824071439914386289373243983185946795491819129870207658214310478641067801668872244606421878692919649372294669971163490263922400626336242549835706388683877132951576008701491480511964700265393284833130226932921133394423802845820376416051352258291552872659169273062675846495338968217135950455977401551939531925192805141513749352229791333923735208796396811016155462890934792375784262889437336581789661289949141905602572787198543216492782644044690961535388836272756550843545526602092242838754566866668770935315676090418730740458031516514972175558292490434340653602286960865392593256844629420033899513449695339367156173095463513078538974962886381545956586331314243000178758164274052565937247768118311842079769519252368952306761435644300926556436608921187592529049031682872480807213750
    x,y,z = solve(res, 1)
    _enc = int(gcd(x, z))
    _hash = int(z // _enc)
    pk = int(y // _hash)
    assert x == _enc  * pk
    assert y == _hash * pk
    assert z == _enc  * _hash
    p, q, r = solve(pk)
    phi = (p - 1) * (q - 1) * (r - 1)
    d = inverse_mod(31337, phi)
    print(long_to_bytes(pow(_enc, d, p * q * r)))

main()
```

And we finally get: `ASIS{I7s__Fueter-PoLy4__c0nJ3c7UrE_iN_p4Ir1n9_FuNCT10n}`

Complete solver [here](solver.sage)
