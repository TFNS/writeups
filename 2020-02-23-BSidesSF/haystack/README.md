# Haystack (crypto/forensics/re, 401p, 8 solved)

A very nice crypto challenge.
We get a [pyc file](chaffing.pyc) with some crypto code, and [network capture](message.pcap) with transmission of encrypted data.

The forensics part is trivial. 
There is literally just one data stream in the pcap, so we simply use `follow TCP stream` feature from wireshark and save the entire [payload](data.bin).

The reverse part is equally simple, we can just run `uncompyle6` on the provided pyc and recover the source code.
There were some small issues with py2/py3 string vs. bytes but eventually we have [working code](chaffing.py)

The code is quite simple to understand:

1. `Encryption` works one byte of plaintext at a time.
2. For each byte a `signature` is calculated, using `hmac with sha256` (with secret key) and leaving `16 bytes` of it.
3. Then 31 `fake` bytes are selected at random, and a random 16 bytes `fake signature` is generated for each of them.
4. Finally all those 32 pairs `byte, signature` are shuffled, and appended to the resulting ciphertext

The decryption process for given byte is quite straightforward as well:

1. Extract 32 pairs `byte, signature`
2. For each one calculate hmac for given byte and compare with the `signature`, the one that matches is the `real` byte.

We don't know the hmac key, so we can't use this method to distinguish between real and fake signature.
However, notice that there is no randomness here, no byte counter included in the hmac signature.
This means we have a ECB-like encryption here.
Every time you encrypt byte `X`, it will have the same signature!

This means that for example every `real` byte `a` will have signature `sig_a`, whereas `fake` bytes have random signatures.
We can, therefore, get list of all signatures for each byte, and then count how often each one of them appears.
The real one should be significantly more common, and therefore we can easily spot it.

We slightly modified given decryption code to extract all pairs:

```python
def extract(val):
    if not isinstance(val, bytes):
        val = val.encode('utf-8')
    msglen = struct.unpack('>I', val[:4])[0]
    val = val[4:]
    chunk_len = (SIG_SIZE + 1) * CHAFF_SIZE
    expected_len = chunk_len * msglen
    if len(val) != expected_len:
        raise ValueError('Expected length %d, saw %d.' % (expected_len, len(val)))
    pieces = []
    for c in range(msglen):
        chunk = val[chunk_len * c:chunk_len * (c + 1)]
        res = extract_byte_sig_pairs(chunk)
        pieces.extend(res)
    return pieces


def extract_byte_sig_pairs(val):
    res = []
    while val:
        c = byte(val[0])
        sig = val[1:SIG_SIZE + 1]
        res.append((c, sig))
        val = val[SIG_SIZE + 1:]
    return res
```

And with this we can simply do:

```python
msg = open('data.bin', 'rb').read()
ret = extract(msg)
c = Counter(ret)
real = c.most_common(256)
print(real)
```

This gives us the list of most common pairs `byte, signature`.

Now we can easily decrypt the data, using the same way the original decryption works. 
The only difference is that we don't calculate hmac signature, but simply take the one we just calculated.

We can make a map `d = {s: b for (b, s), c in real}` which given signature tells us what byte it should be, and then plug this in decryption:


```python
def decode(val, d):
    if not isinstance(val, bytes):
        val = val.encode('utf-8')
    msglen = struct.unpack('>I', val[:4])[0]
    val = val[4:]
    chunk_len = (SIG_SIZE + 1) * CHAFF_SIZE
    expected_len = chunk_len * msglen
    if len(val) != expected_len:
        raise ValueError('Expected length %d, saw %d.' % (expected_len, len(val)))
    pieces = []
    for c in range(msglen):
        chunk = val[chunk_len * c:chunk_len * (c + 1)]
        res = decode_byte(chunk, d)
        pieces.append(res)
    return b''.join(pieces)


def decode_byte(val, d):
    while val:
        c = byte(val[0])
        sig = val[1:SIG_SIZE + 1]
        if sig in d and d[sig] == c:
            return c
        val = val[SIG_SIZE + 1:]
    raise ValueError("WTF")
```

This way we recover the message:

```
b'\x105.8\xd2\xae\xcessage is encoded using a technique called "Chaffing and Winnowing"[1],\na technique that was first published by Ron Rivest in an article published on\nthe 18th of March 1998 (1998/03/18).  Unfortunately, my implementation of the\ntechnique suffers from very significant flaws, not the least of which is the\nfailure to include a counter within the the MAC\'d portion of the data.  This\nleads to all valid bytes with the same value having the same MAC, which should\nallow for a fairly trivial frequency analysis attack on the message.\nUltimately, if you\'re reading this, then you\'ve found *some* way to crack the\nencoding applied here.\n\nChaffing and winnowing also leads to a pretty major blow up in size.  Imagine\nif, instead of 31 bytes of chaff per byte of message, I had used the maximum\n255.  Imagine that I used a 256-bit MAC instead of 128.  (256 bits: military\ngrade crypto!!@!)\n\nAt this point, you\'ve been patient enough through my diatribe (which is really\njust to give you the plaintext you need to launch your attack against the output\nof this encoding).  What you\'re really here for is the FLAG.  Like most of our\nother flags, this is in the typical CTF{} format.\n\nCTF{thanks_to_rivest_for_all_his_contributions}\n\n- Matir.\n(@Matir, https://systemoverlord.com)\n\nGreetz to decreasedsales, dissect0r, poptart, ehntoo, illusorycake, and\nzerobitsmith.\n\n\n[1]: https://en.wikipedia.org/wiki/Chaffing_and_winnowing\n'
```

And the flag is `CTF{thanks_to_rivest_for_all_his_contributions}`
