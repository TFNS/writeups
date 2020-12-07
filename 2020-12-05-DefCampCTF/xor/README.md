# Why XOR (crypto, 50p, 134 solved)

## Description

```
Let's be fair, we all start with XOR, and we keep enjoying it.

Flag format: CTF{sha256}
```

In the task we get a simple [python script](xor.py)

## Task analysis

The idea is pretty simple - flag was XORed with some unknown keystream.
The hint suggests that first 3 bytes of the keystream are the same as first 3 bytes of the flag.

## Solution

We could assume that flag prefix is `CTF` as stated in the task description.
This proves to be invalid assumption, because it turnes out we should have guessed that it's actually `ctf` instead.

Although code does not suggest it, we can also guess that the XOR key is repeated:

```python
    xored = ['\x00', '\x00', '\x00', '\x18', 'C', '_', '\x05', 'E', 'V', 'T', 'F', 'U', 'R', 'B', '_', 'U', 'G', '_', 'V', '\x17', 'V', 'S', '@', '\x03', '[',
             'C', '\x02', '\x07', 'C', 'Q', 'S', 'M', '\x02', 'P', 'M', '_', 'S', '\x12', 'V', '\x07', 'B', 'V', 'Q', '\x15', 'S', 'T', '\x11', '_', '\x05',
             'A', 'P', '\x02', '\x17', 'R', 'Q', 'L', '\x04', 'P', 'E', 'W', 'P', 'L', '\x04', '\x07', '\x15', 'T', 'V', 'L', '\x1b']
    keystream = 'ctf'
    data = ''.join(xored)
    print(xor_string(keystream * 100, data))
```

And we get `ctf{79f107231696395c004e87dd7709d3990f0d602a57e9f56ac428b31138bda258}`
