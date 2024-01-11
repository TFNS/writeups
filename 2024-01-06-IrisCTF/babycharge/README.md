# Baby Charge - IrisCTF 2024 (crypto, 151 solved, 50p)

## Introduction
Baby Charge is a cryptography task.

A Python script reimplementing the ChaCha20 stream cipher. It is not the
version described in [RFC7539](https://datatracker.ietf.org/doc/html/rfc7539)

The script generates a random key and iv, then it acts as an encryption oracle.
There is an option to encrypt the flag.

## Analysis
The algorithm implemented in the given script differs from the standard
implementation of ChaCha20. Most noticeably, it does not properly initialize the
state before encryption. On top of that, the block counter variable is never
incremented.

Because of these vulnerabilities, encrypting a message of 64 bytes will leak the
internal state of the algorithm:

```python
def encrypt(data):
    global state, buffer

    output = []
    for b in data:
        if len(buffer) == 0:
            buffer = b"".join(long_to_bytes(x).rjust(4, b"\x00") for x in state)
            state = chacha_block(state)
        output.append(b ^ buffer[0])
        buffer = buffer[1:]
    return bytes(output)
```

## Exploitation
It is possible to retrieve the internal state of the algorithm by sending a
buffer and xoring the output with this buffer. Once the internal state is known,
it can be used to decrypt any message.

The attack consists in encrypting a 64-bytes buffer to recover the state,
encrypt the flag and use the leaked state to decrypt it.

**Flag**: `irisctf{initialization_is_no_problem}`

## Appendices
### pwn.py
```python
from chal import encrypt, state
from Crypto.Util.number import long_to_bytes, bytes_to_long

# encrypted A * 64
x = bytes.fromhex('203139247261252f38236c732a6124357e4eca28289d3d3dadcc03d9c386d0f37fc29479484290964f622cc55f104e2f4141414141414141c9e4e817b90676b2')
# encrypted flag
flag = bytes.fromhex('1831bce92152968a71ffc79edf53df403b80d393965aba31f3230de3525542bbd1883f9250')

# retrieve state
y = bytes([_ ^ 0x41 for _ in x])

for i in range(len(state)):
	state[i] = bytes_to_long(y[4 * i:4 * i + 4])

# replay A
encrypt(("A" * 64).encode()).hex()

# print flag
print(encrypt(flag))
```
