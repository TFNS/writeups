#!/usr/bin/python

from Crypto.Util.number import *
import random
from flag import flag

p = 22883778425835100065427559392880895775739

flag_b = bin(bytes_to_long(flag))[2:]
l = len(flag_b)

enc = []
for _ in range(l):
	a = [random.randint(1, p - 1) for _ in range(l)]
	a_s = 1
	for i in range(l):
		a_s = a_s * a[i] ** int(flag_b[i]) % p
	enc.append([a, a_s])

f = open('flag.enc', 'w')
f.write(str(p) + '\n' + str(enc))
f.close()