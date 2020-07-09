#!/usr/bin/python

from Crypto.Util.number import *
import random
from flag import flag

sv = bin(bytes_to_long(flag[5:-1]))[2:]
nbit = len(sv)
q = 39485091642302322462443783940079058526663151328744488399920207767

r = random.randint(2*nbit, 3*nbit)
enc = []
for _ in range(r):
	a = [random.randint(1, q-1) for _ in range(nbit)]
	a_s = 1
	for i in range(nbit):
		a_s = a_s * a[i] ** int(sv[i]) % q
	enc.append([a, a_s])

f = open('flag.enc', 'w')
f.write(str(q) + '\n' + str(enc))
f.close()