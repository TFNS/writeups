# KeySharer (crypto)

## Introduction

In the task we get [source code](keysharer.py) of a service which performs ECC-based key agreement.
We can provide it with 4 public points, which will be used to generate a shared secret for us.
The flag is encoded as base point which we don't know.

## Analysis

The whole protocol seems a bit weird, since it doesn't really provide any security.
Flag is used as generator point `G` on `NIST 192-P`, then a secret random integer `PK` is selected and `G` is multiplied by it.
We receive `PK*G` as Alice public key.
We can now provide 4 points `Xi` and receive back `PK*Xi`

We would like to recover `G` which means we need to recover `PK` first.
Once we have PK we can simply multiply `PK*G` by inverse of `PK` mod order of `NIST 192-P`.

The only information about `PK` comes from `PK*Xi`.
We can do that 4 times, which means we need to leak at least 48 bits of `PK` each time to get all 192 bits.

## Solution

The solution is hinted by the service code itself, because we're asked about both corrdinates of our points and those are not verified.
In the service itself when converting flag to a point there is a check:

```python
assert pow(y_squared, (self.p - 1) // 2, self.p) == 1, "The x coordinate is not on the curve"
```

which is missing when parsing points we provide.

This leads to a well known "invalid curve attack".
The idea is that we can generate low order points which are on a different curve.
We can pick a curve with smooth order and pick a point with low order, so that computing discrete logarithm for that particular point will be easy for us:


```sage
b = randint(1, p)
E = EllipticCurve(GF(p), [a, b])
order = E.order()
factors = prime_factors(order)
small_factors = []
for factor in factors:
    if factor<= 2**30:
        small_factors.append(factor)
prod = Integer(math.prod(small_factors))
if prod.nbits() < 48: # we need 192 bits in 4 payloads
    continue
print('Found decent curve with b=', b)
Xi = E.gen(0) * int(order / prod) # low order point, we get rid of big factors
print(Xi)
```

We can repeat this process until we find 4 decent points.

We've noticed some rather confusing articles on the internet about this, so for clarification:

1. We don't need the order of the curve to be completely smooth (factoring only into small primes), because we can multiply the generator point by the product of big factors of the order, making the point low order. This of course means that we will know the discrete logarithm only modulo product of small factors, but we only need to recover 48 bits from one point.
2. At the same time we don't need the point order to be prime, so there is no reason to pick only one of the factors. We can use all small factors, sage's pohlig-hellman will handle this for us just fine.

With such point we can submit it to the server and get back `PK*Xi`, on which we can compute discrete logarithm and recover `partial = PK mod prod`.
We store this result in a list of `(partial % factor, factor)` for all small factors we used, because we will need this later for CRT.

Once we do this for all 4 points we can use CRT to combine all partial results we got and recover `PK`:

```sage
import re
import socket
import telnetlib
import math
import random

def nc(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def send(s, payload):
    s.sendall((payload + "\n").encode())

    
def solver():
    s = nc("chall.polygl0ts.ch", 9025)
    data = s.recv(999999)
    alice = re.findall("\\d+",data.decode())[1:]
    p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    primes = []
    logs = []
    bs = []
    while len(bs)<4:
        b = randint(1, p)
        E = EllipticCurve(GF(p), [a, b])
        order = E.order()
        factors = prime_factors(order)
        small_factors = []
        for factor in factors:
            if factor<= 2**30:
                small_factors.append(factor)
        prod = Integer(math.prod(small_factors))
        if prod.nbits() < 48: # we need 192 bits in 4 payloads
            continue
        print('Found decent curve with b=', b)
        bs.append(b)
        G = E.gen(0) * int(order / prod)
        print(G)
        send(s,str(G[0]))
        print(s.recv(9999))
        send(s,str(G[1]))
        Q = re.findall("\\d+",s.recv(9999).decode())
        print(Q)
        Q = E(Q[0],Q[1])
        log = G.discrete_log(Q)
        print(f"DL found: {log}")
        for prime in small_factors:
            primes.append(prime)
            logs.append(log%prime)
    PK = CRT_list(logs, primes)
    print(PK)
    order = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    E = EllipticCurve(GF(p), [a, b])
    alice = E(alice[0], alice[1])
    d = inverse_mod(PK, order)
    base_point = alice * d
    flag = binascii.unhexlify(Integer(base_point[0]).hex())
    print(flag)
    
solver()
```

`EPFL{th1s_1s_1nv4lid}`
