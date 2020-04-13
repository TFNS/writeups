# Meet me there (crypto, 232p)

In the task we get [code](meet.py) and results:

```
Give me a string:
aaaaaaaaaaaaaaaa
Encrypted string:
ef92fab38516aa95fdc53c2eb7e8fe1d5e12288fdc9d026e30469f38ca87c305ef92fab38516aa95fdc53c2eb7e8fe1d5e12288fdc9d026e30469f38ca87c305

Encrypted Flag:
fa364f11360cef2550bd9426948af22919f8bdf4903ee561ba3d9b9c7daba4e759268b5b5b4ea2589af3cf4abe6f9ae7e33c84e73a9c1630a25752ad2a984abfbbfaca24f7c0b4313e87e396f2bf5ae56ee99bb03c2ffdf67072e1dc98f9ef691db700d73f85f57ebd84f5c1711a28d1a50787d6e1b5e726bc50db5a3694f576
```

The idea of the code is rather simple:

1. Two separate AES keys are generated, each one with just 3 bytes secret
2. Flag is encrypted by one, and then by the other
3. We also get a single plaintext-ciphertext pair

## Expected solution

We solved this via a simple meet-in-the-middle attack, but there is a weird thing in the code, which makes it even simpler than it was supposed to be -> payloads are hex-encoded before the encryption both times.

The idea of meet-in-the-middle is that we can:

- For all possible key1 values encrypt the known plaintext, and store the results in a lookup map as `ciphertext -> key1`
- For all possible key2 values decrypt the known ciphertext, and check if the result is in the lookup map we created

If there is a match, it means we found such `key2` that when we decrypt the ciphertext we know, we get plaintext encrypted by `key1` and thus we know both keys:

```python
def first_half():
    pt = 'aaaaaaaaaaaaaaaa'
    val = len(pt) % 16
    if not val == 0:
        pt += '0' * (16 - val)
    res = {}
    for a in printable:
        for b in printable:
            for c in printable:
                key1 = '0' * 13 + a + b + c
                cipher1 = AES.new(key=key1, mode=AES.MODE_ECB)
                c1 = cipher1.encrypt(pt.encode('hex')).encode("hex")
                res[c1] = key1
    return res


def second_half(first_half):
    ct = "ef92fab38516aa95fdc53c2eb7e8fe1d5e12288fdc9d026e30469f38ca87c305ef92fab38516aa95fdc53c2eb7e8fe1d5e12288fdc9d026e30469f38ca87c305".decode("hex")
    for a in printable:
        for b in printable:
            for c in printable:
                key2 = a + b + c + '0' * 13
                cipher2 = AES.new(key=key2, mode=AES.MODE_ECB)
                res = cipher2.decrypt(ct)
                if res in first_half:
                    key1 = first_half[res]
                    return key1, key2
```

Once we have both keys we can decrypt flag: `flag{y0u_m@d3_i7_t0_7h3_m1dddl3}`

## Unintended solution

Because of the mistake, there was a solution slightly easier: since payloads were hexencoded before encryption, it means the decrypted data would be hexencoded string!
So if we decrypt the flag using all possible `key2` values, only one of them will give us a nice hex-encoded string.
Then we can proceed in the same way with this string, to look for the all possible `key1` values:

```python
def unintended():
    flag = 'fa364f11360cef2550bd9426948af22919f8bdf4903ee561ba3d9b9c7daba4e759268b5b5b4ea2589af3cf4abe6f9ae7e33c84e73a9c1630a25752ad2a984abfbbfaca24f7c0b4313e87e396f2bf5ae56ee99bb03c2ffdf67072e1dc98f9ef691db700d73f85f57ebd84f5c1711a28d1a50787d6e1b5e726bc50db5a3694f576'.decode(
        "hex")
    for a in printable:
        for b in printable:
            for c in printable:
                key2 = a + b + c + '0' * 13
                cipher2 = AES.new(key=key2, mode=AES.MODE_ECB)
                x = cipher2.decrypt(flag)
                if len(set(x).difference(string.hexdigits)) == 0:
                    print("Found second", key2)
                    for a in printable:
                        for b in printable:
                            for c in printable:
                                key1 = '0' * 13 + a + b + c
                                cipher1 = AES.new(key=key1, mode=AES.MODE_ECB)
                                y = cipher1.decrypt(x.decode("hex"))
                                if len(set(y).difference(string.hexdigits)) == 0:
                                    print("Found first", key1)
                                    print(y.decode("hex"))
                                    sys.exit(0)
```

[complete solver here](solver.py)
