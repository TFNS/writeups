from flag import flag, key
from Crypto.Cipher import DES
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import os
from gmpy2 import is_prime
import random
import base64

m = getPrime(512)

while(m%4 != 3 or not is_prime(m)):
	m += 1

l = [x for x in range(0, 1024, 8)]

random.shuffle(l)

l2 = []

for i in range(128):
	l2.append(hex(pow(bytes_to_long(key[i*8:(i+1)*8] + long_to_bytes(l[i])), 65536, m)))

def pad(s):
	while(len(s)%8 != 0):
		s+=long_to_bytes(len(s)%256)
	return s

def encrypt(plaintext):
	ciphertext = pad(plaintext)
	for i in range(128):
		cipher = DES.new(key[l[i]:l[i]+8], DES.MODE_ECB)
		ciphertext = cipher.encrypt(ciphertext)

	return ciphertext

def main():
	print("Welcome!\n")
	print("1. Encrypt String")
	print("2. Get Key")
	print("3. Get encrypted flag")
	print("4. Exit")
	print()
	while(True):
		ch = input('> ')
		if(ch == '1'):
			s = input('String : ').encode()
			print(base64.b64encode(encrypt(s)).decode())
		elif(ch == '2'):
			print(hex(m)+'\n' + str(l2))
		elif(ch == '3'):
			print(base64.b64encode(encrypt(flag)).decode())
		else:
			exit(0)


if(__name__ == '__main__'):
	main()

