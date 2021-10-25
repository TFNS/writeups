# Spirit (crypto, 79p, 60 solved)

## Description

```
The meaning of spirituality has developed and expanded over time, but what does it mean here?
```

## Task analysis

In the task we connect to remote and see:

```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+   hello, you know valuable information about given elliptic curve,   +
+   your mission is to answer the question in each stage quickly!      +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
| E is an elliptic curve with k elements in the following form:
| E: y**2 = x**3 + a*x + b (mod p)
| p = 7146799136999232629
| a = ?
| b = ?
| k = 7146799140008663196
| What's the number of elements of E over finite field GF(p**n) where n = 13?
```

We need to solve a bunch of questions of this type to get the flag.

The idea is that we don't know the exact curve, only number of points it has over `GF(p)`, and from that we need to estimate number of points over `GF(p^n)`

## Solution

### Observations

First clue on how this can be solved comes from looking at `cardinality` function in `sage`, specifically that it has a parameter `extension_degree`, which does exactly what we would like to do.

Of course we can't use this, because we don't know the exact curve in question, but it's an interesting idea to check how this `extension_degree` is used.
Sadly https://github.com/sagemath/sagesmc/blob/master/src/sage/schemes/elliptic_curves/ell_finite_field.py#L838 doesn't look very appealing with lots of function calls all over, but it gives us another hint that we're looking for something related to `frobenius`, and we're looking for order of cardinality of elliptic curve over finite field extension.

A bit of googling takes us to: https://math.stackexchange.com/questions/144194/how-to-find-the-order-of-elliptic-curve-over-finite-field-extension which is exactly what we need.

### Solver

We proceed to implement described algorithm:

```python
def frobenius(p,k):
    return p+1-k

def compute_extension(p,k,n):
    t = frobenius(p,k)
    s = [2,t]
    for i in range(2,n+1):
         s.append(t*s[i-1]-p*s[i-2])
    return  p**n +1 - s[n]
```

And we can verify this with a simple sanity check:

```python
def sanity():
    p = 7146799136999232629
    E = EllipticCurve(GF(p), [1,2])
    k = E.cardinality()
    n = 13
    assert compute_extension(p,k,n) == E.cardinality(extension_degree=n)
```

### Plugging it all together

Now we can connect this with communication code:

```python
import re
import telnetlib
import socket

def interactive(s):
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

def nc(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def frobenius(p,k):
    return p+1-k

def compute_extension(p,k,n):
    t = frobenius(p,k)
    s = [2,t]
    for i in range(2,n+1):
         s.append(t*s[i-1]-p*s[i-2])
    return  p**n +1 - s[n]

def main():
    s = nc("168.119.108.148",13010)
    data = s.recv(9999)
    for i in range(20):
        data = s.recv(9999)
        p = int(re.findall(b"p = (\d+)",data)[0])
        k = int(re.findall(b"k = (\d+)",data)[0])
        n = int(re.findall(b"n = (\d+)",data)[0])
        ext = compute_extension(p,k,n)
        print(p,k,n,ext)
        s.sendall((str(ext)+"\n").encode())
        print(s.recv(9999))
    interactive(s)
    s.close()

main()
```

And after a moment we get: `ASIS{wH47_iZ_mY_5P1R!TuAL_4NiMal!???}`
