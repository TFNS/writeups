#!/usr/bin/python

from Crypto.Util.number import *
from flag import flag
from secret import *

def encrypt(msg, pubkey, xorkey):
	h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1	# dirty log :/
	m = bytes_to_long(msg)
	if len(bin(m)[2:]) % h != 0:
		m = '0' * (h - len(bin(m)[2:]) % h) + bin(m)[2:]
	else:
		m = bin(m)[2:]
	t = len(m) // h
	M = [m[h*i:h*i+h] for i in range(t)]
	r = random.randint(1, pubkey)
	s_0 = pow(r, 2, pubkey)
	C = []
	for i in range(t):
		s_i = pow(s_0, 2, pubkey)
		k = bin(s_i)[2:][-h:]
		c = bin(int(M[i], 2) ^ int(k, 2) & xorkey)[2:].zfill(h)
		C.append(c)
		s_0 = s_i
	enc = int(''.join(C), 2)
	return (enc, pow(s_i, 2, pubkey))

for keypair in KEYS:
	pubkey, privkey, xorkey = keypair
	enc = encrypt(flag, pubkey, xorkey)
	msg = decrypt(enc, privkey, xorkey)
	if msg == flag:
		print pubkey, enc
