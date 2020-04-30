# Plaint..image (crypto, 620p, 27 solved)

```
Hey! 
I encrypted this photo using simple XOR, but im sure its safe, 
i used 40 byte key after all, no one would ever be able to bruteforce that ;)
```

Pretty standard challenge, we have a [jpeg image](flag.jpg.enc) encrypted with 40-bytes long repeating key XOR.

The idea is rather simple:

- Use some known plaintext bytes (eg. file header) to recover part of the keystream
- XOR known keystream bytes with ciphertext
- Hope that this uncovers some new plaintext parts of the data, which we can "extend"

We run:

```python
from crypto_commons.generic import xor_string, chunk_with_remainder

data = open("flag.jpg.enc", 'rb').read()
jpg_header = 'FF D8 FF E0 00 10 4A 46 49 46 00 01'.replace(" ", "").decode("hex")
key = xor_string(data, jpg_header)
extended_key = key + ("\0" * (40 - len(key)))
chunks = chunk_with_remainder(data, 40)
for c in chunks:
    print(xor_string(extended_key, c))
```

And we can see two interesting chunks:

```
STUVWXYZcdef...
()*56789:CDE...
```

If we look inside some example JPG files with hexeditor we can see that such data in fact appear there, and that they are much longer!
We can use one of them -> `()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxy` to recover entire keystream and decrypt the flag:

```python
extended_key = xor_string(chunks[15], "()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxy")
open('out.jpg', 'wb').write(xor_string(data, extended_key * 1000))
```

And we get:

![](out.jpg)
