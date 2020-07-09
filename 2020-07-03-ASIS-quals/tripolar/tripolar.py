#!/usr/bin/python

from Crypto.Util.number import *
from hashlib import sha1
from flag import flag

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

key = keygen(256)
enc = encrypt(flag, key)
f = open('flag.enc', 'w')
f.write(long_to_bytes(enc))
f.close()