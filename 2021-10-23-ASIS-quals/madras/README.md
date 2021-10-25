# Madras (crypto, 59p, 88 solved)

## Description

```
Madras is a great place to learn the occult! 
The occult, is a category of supernatural beliefs and practices which generally fall outside the scope of religion and science. 
Do you want to go Madras?
```

## Task analysis

In the task we get [source code](Madras.py) and [output](output.txt).
The encryption code is:

```python
def encrypt(msg, params):
    a, b, c = params
    e, n = 65537, a * b * c
    m = bytes_to_long(msg)
    assert m < n
    enc = pow(m, e, n)
    return enc
```

This is essentially mutliprime RSA, nothing special here.

What we also know is:

```
a*b + c
b*c + a
c*a + b
```

(And also `enc mod a`, `enc mod b` and `enc mod c` but those are useless)

The goal is to recover `a,b,c` so we can calculate RSA decryption exponent.

## Solution

### Observations

It's pretty clear that we have a simple equation here.
We can for example use the first equation and transform:

```
a*b + c = X
c = X-a*b
```

Then we can plug-in this `c` into second equation
```
b*c + a = Y
b*(X-a*b) + a = Y
bX - ab^2 + a = Y
bX - a(b^2+1) = Y
a(b^2+1) = bX - Y
a = (bX - Y)/(b^2+1)
```

And finally we can plug our `a` and `c` into the last equation to get a final equation based only on variable `b`, which we can then solve.

### Solver

The numbers are big, and it's easy to make a mistake, so we simply plug this into sage:

```sage
var('a b c')
X = 4553352994596121904719118095314305574744898996748617662645730434291671964711800262656927311612741715902
Y = 4414187148384348278031172865715942397786003125047353436418952679980677617016484927045195450392723110402
Z = 2621331497797998680087841425011881226283342008022511638116013676175393387095787512291008541271355772802

eq1 = X == a * b + c
eq2 = Y == b * c + a
eq3 = Z == c * a + b
solve([eq1, eq2, eq3], a, b, c)
```

And we get:

```
[
    [a == 1644376501336761869533914527999140316946467005479211, 
    b == 2769045283056871559108237639832652911114008081576651, 
    c == 1594118801665580510615541222527591707834932058213541]
]
```

We can do a sanity check with known relations:

```
assert (enc % a == 1235691098253903868470929520042453631250042769029968)
assert (enc % b == 2235727505835415157472856687960365216626058343546572)
assert (enc % c == 1197976933648163722609601772402895844093866589777721)
```

Now we can just proceed as with any multiprime RSA:

```python
n = a * b * c
phi = (a - 1) * (b - 1) * (c - 1)
d = modinv(65537, phi)
print(long_to_bytes(pow(enc, d, n)))
```

And we get `ASIS{m4dRa5_iZ_RSA_l1k3_cH41L3n9E?!!}`