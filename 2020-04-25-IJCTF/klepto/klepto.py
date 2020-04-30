#!/usr/bin/env python3

from random import getrandbits, randrange

def generate():
	IV = 5326453656607417485924926839199132413931736025515611536784196637666048763966950827721156230379191350953055349475955277628710716247141676818146987326676993279104387449130750616051134331541820233198166403132059774303658296195227464112071213601114885150668492425205790070658813071773332779327555516353982732641; seed = 0; temp = [0, 0]; key = 0
	while(key != 2):
		if key == 0:
			seed = getrandbits(1024) | (2 ** 1023 + 1)
		seed_ = seed ^ IV; n = seed_ << 1024 | getrandbits(1024); seed = n//seed | 1
		while(1):
			seed += 2; pi = seed - 1; b = 0; m = pi;
			while (m & 1) == 0:
				b += 1
				m >>= 1
			garbage = []; false_positive = 1
			for i in range(min(10, seed - 2)):
				a = randrange(2, seed)
				while a in garbage:
					a = randrange(2, seed)
				garbage.append(a); z = pow(a, m, seed)
				if z == 1 or z == pi:
					continue
				for r in range(b):
					z = (z * z) % seed;
					if z == 1:
						break
					elif z == pi:
						false_positive = 0; break
				if false_positive:
					break
			if not false_positive:
				break
		temp[key] = seed; key += 1
	return(temp[0], temp[1])

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def inverse(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m

def RSA():
	(p, q) = (0, 0)
	while(p == q):
		(p, q) = generate()
	n = p * q
	e = 0x10001
	d = inverse(e, (p - 1) * (q - 1))

	return (n, e, d)