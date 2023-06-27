# Pallas (crypto, 12 solves, 263p)

## Introduction

In the task we get some custom symmetric encryption with a known plaintext-ciphertext pair, and secret key.

## Task analysis

```python
from sec import secret
print(len(secret))

text   = b"The Pallas's cat is a highly specialised predator of small mammals, which it catches by stalking or ambushing near exits of burrows."

def bits_to_bytes(l):
	l = [str(f) for f in l]
	l="".join(l)
	final = [l[i * 8:(i + 1) * 8] for i in range((len(l) + 8 - 1) // 8 )]
	final = [int(x,2) for x in final]
	return bytes(final)

def bytes_to_bits(bb):
	r = ""
	for c in bb:
		r += bin(c)[2:].rjust(8,"0")
	r= list(map(int, r))
	return r

def my_crypto_inner(text, secret):
	tl = len(text)
	sl = len(secret)
	enc = [0]*len(text)
	for i in range(tl):
		enc[i]=text[i]
		enc[i]^=secret[i % sl]
		for div in range(1, tl):
			if i%div == 0:
				enc[i] ^= enc[(i-div) % sl]
			if i>0 and div%i == 0:
				enc[i] ^= text[(i-div) % sl]
	return enc

def my_crypto(text, secret):
	text = bytes_to_bits(text)
	secret = bytes_to_bits(secret)
	res = my_crypto_inner(text,secret)
	return bits_to_bytes(res)

encrypted = my_crypto(text,secret)
print(encrypted)
```

The algorithm turns plaintext and secret into bits and then performs a bunch of XORs.
There are some conditionals in the code, but they are "fixed" because depend only on the index and not on some unknown value.
Apart from the ciphertext we also know the length of `secret` to be `62`

## Solution

We could try to invert the `my_crypto_inner` function, but we're too lazy for that.
Instead we can simply feed-forward the cipher with z3 BitVecs and ask z3 to find the matching secret:

```python
def main():
    encrypted = b'_\xce\x80^\x86\x8b\xbe\x00\x15I\xa7]\x86M\x1f\xe8\x87\x8e\xa3\xec_\x8d\x8a\xbd\xd4\xe7\x923\xa1\x8cw\x15F\x06\x8a\xa87\xa6\xcd)/\xaf\xce\xbc\x90go\xc4\r(\xac\xb1ng\xd5\x88\\\x07\xa9z\\G\x8d\xc2\x9f\x9c\x89\xf8r\x87Ut\xf5\xdc\xdda9\xe0\xc5\xa0G\xb8\xf6\xbe\n\xb1\xd0\xdc-\xd6\xfc\x15\x13\xbf}\xbf5\xb0S\x94\x0e\x98\x9a\x12\xd0\x9e\xdf\xba3\xd8\x8b\x0eR\x87$\xb3\xd6\xcd\xef\x92\xa1\xa3|\xb4-\n\xdbw\x86{DE'
    sec = [BitVec(f's{i}', 1) for i in range(62 * 8)]
    enc = bytes_to_bits(encrypted)
    t = bytes_to_bits(text)
    res = my_crypto_inner(t, sec)
    s = z3.Solver()
    for i in range(len(enc)):
        s.add(enc[i] == res[i])
    print(s.check())
    model = s.model()
    bits = [model[x].as_long() for x in sec]
    print(bits_to_bytes(bits))


main()
```

And almost immediately we get back: `p4{It_4ls0_pu1ls_0ut_rodeNts_with_ITs_pawsFromShallowBurrows.}`
