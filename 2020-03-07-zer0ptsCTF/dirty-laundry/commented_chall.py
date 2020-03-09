#!/usr/bin/sage
from sage.all import *
from Crypto.Util.number import getStrongPrime, bytes_to_long

from secret import flag

class PRNG256(object):
    def __init__(self, seed):
        self.mask = (1 << 256) - 1
        self.seed = seed & self.mask

    def _pick(self):
        b = ((self.seed>>0)^(self.seed>>2)^(self.seed>>5)^(self.seed>>10)^1)&1
        self.seed = ((self.seed>>1)|(b<<255)) & self.mask
        return b

    def rand(self):
        x = 0
        for i in range(256):
            x = (x << 1) | self._pick()
        return x

PRIME = getStrongPrime(1024)
prng = PRNG256(PRIME)

def paillier_enc(m, p, noise):
    p = next_prime(p + noise)
    q = getStrongPrime(512)
    n = p * q
    # g is much smaller than n**2, so we can retrieve prng.rand() for each
    # share
    g = (1 + prng.rand() * n) % n**2
    # Here we can find all the m from (1 + n)^x = 1 + nx [n^2]
    # <=> (1 + kn)^x = 1 + knx [(kn)^2]
    c = pow(g, m, n**2) * pow(prng.rand(), n, n**2) % n**2
    return n, g, c

# (p * q1) = n1 - (noise1 * q1)

# (p + noise1) * q1 = n1
# (p + noise2) * q2 = n2
# (p + noise3) * q3 = n3

# given one output of PRNG256.rand(), we retrieve the seed for the next calls
# as such:
# y = PRNG256(int(bin(out)[2:].zfill(256)[::-1], 2))
# earliest we can retrieve is from the first g, by taking out = (g - 1) / n.
# Then it can be reverted to find the noise & the low 256 bits of p.
# Then the problem is DLP, but an easy instance.


# From the m, we can deduce the shares:
# x = 1, a    + b   + c = m1 [prime]
# x = 2, a*4  + b*2 + c = m2 [prime]
# x = 3, a*9  + b*3 + c = m3 [prime]
# x = 4, a*16 + b*4 + c = m4 [prime]
# x = 5, a*25 + b*5 + c = m5 [prime]

def make_shares(secret, k, shares, prime=PRIME):
    PR, x = PolynomialRing(GF(prime), name='x').objgen()
    f = PR([secret] + [ZZ.random_element(prime) for _ in range(k-1)])
    xy = []
    pubkey = []
    # Loop of length five
    for x in range(1, shares+1):
        noise = prng.rand()
        n, g, y = paillier_enc(f(x) + noise, prime, noise)
        pubkey.append([n, g])
        # x is the polynomial parameter and c the ciphertext
        xy.append([x, y])
    return pubkey, xy

secret = bytes_to_long(flag)
pubkey, shares = make_shares(secret, 3, 5)

print("[+] len(flag):", len(flag))
print("[+] pubkey:", pubkey)
print("[+] shares:", shares)
