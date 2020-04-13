#!/usr/bin/python

import random
from Crypto.Cipher import AES
from os import urandom
from string import printable

random.seed(urandom(32))

key1 = '0'*13 + ''.join([random.choice(printable) for _ in range(3)])
key2 = ''.join([random.choice(printable) for _ in range(3)]) + '0'*13

cipher1 = AES.new(key=key1, mode=AES.MODE_ECB)
cipher2 = AES.new(key=key2, mode=AES.MODE_ECB)

print "\nGive me a string:"
pt = raw_input()

val = len(pt) % 16
if not val == 0:
    pt += '0'*(16 - val)

c1 = cipher1.encrypt(pt.encode('hex'))
c2 = cipher2.encrypt(c1.encode('hex'))
print 'Encrypted string:\n' + c2.encode('hex')

with open("flag.txt") as f:
    flag = f.read().strip()
# length of flag is a multiple of 16
ct1 = cipher1.encrypt(flag.encode('hex'))
ct2 = cipher2.encrypt(ct1.encode('hex'))
print '\nEncrypted Flag:\n' + ct2.encode('hex') + '\n'

