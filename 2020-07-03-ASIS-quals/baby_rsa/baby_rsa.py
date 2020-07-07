#!/usr/bin/python

from Crypto.Util.number import *
import random
from flag import flag

nbit = 512
while True:
	p = getPrime(nbit)
	q = getPrime(nbit)
	e, n = 65537, p*q
	phi = (p-1)*(q-1)
	d = inverse(e, phi)
	r = random.randint(12, 19)
	if (d-1) % (1 << r) == 0:
		break

s, t = random.randint(1, min(p, q)), random.randint(1, min(p, q))
t_p = pow(s*p + 1, (d-1)/(1 << r), n)
t_q = pow(t*q + 4, (d-1)/(1 << r), n)

print 'n =', n
print 't_p =', t_p
print 't_q =', t_q
print 'enc =', pow(bytes_to_long(flag), e, n)