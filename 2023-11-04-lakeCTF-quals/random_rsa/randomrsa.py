#!/usr/bin/env -S python3 -u
import os
from Crypto.Util.number import isPrime, bytes_to_long
import random

def getPrime(n_bits, verbose=False):
    while True:
        a = random.getrandbits(n_bits)
        if isPrime(a):
            return a
        elif verbose:
            print(f"Sadly, {a} was not prime")

p = getPrime(1024, verbose=True)
q = getPrime(1024)

flag = os.getenv("flag","EPFL{fake_flag}").encode()
n = p * q
e = 65537
print(f"Ciphertext: {pow(bytes_to_long(flag), e, n)}")