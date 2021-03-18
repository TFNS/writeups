# Chilly Beef Code (crypto, 994p, 27 solved)

## Description

```
It looks like encrypted tokens are produced by appending a secret value to input. I've been trying to find the secret value so I can access the system, but the crypto is too powerful.

nc crypto.utctf.live 4355
```

## Task analysis

We can connect to the server, which accepts hex-encoded inputs and returns some hex-encoded payloads.
We assume that it's CBC encryption of some sort of our inputs with flag appeneded at the end.
The curious part is that first byte seems to be iterating:

```
AA
540f995ea0d282e5d29c271995fc4db05e9a28633d8851e14a69f7cb58abac6822d814450bb997b621a3f00d9d5fc831ea766855f557432c26babb3e5f2fd043
AA
550f995ea0d282e5d29c271995fc4db0f2768aeed8e65ca24f77aea31f5b0d1116151af206ceab1abb9e438eaeed08679534777c03fa250a3124df9734061dc5
AA
560f995ea0d282e5d29c271995fc4db0e76fdf41fce247e6fff8aa27bd7ab62214de3025a822953a033af3a05214002deb8ba1cc6d1536bb81bb001c5fdd74b2
```

Out working assumption is that IV is predictable and is just `+1` from previous value.
This means we can look at this as ECB encryption and for ECB there is an easy way to recover a suffix.

## Solution

The way to recover a suffix in ECB encryption requires pushing secret characters out of block.
Let's assume we encrypt blocks: `[AAAAAAAA][AAAAAAAS][ECRET000]` and then we encrypt `[AAAAAAAA][AAAAAAA?][SECRET00]` where we set as `?` all possible values from charset.
It's quite clear that once we hit `S` the encrypted block we got at the beginning and this block we just got will be identical.
This way we know the first letter of secret is `S`.
Now we can shift left by 1 character and perform exactly the same operation.

Here we have a twist, because it's CBC and not ECB.
But because we know how the IV changes, we can easily modify our first character to reflect this.
If we initially sent first byte `X` and the IV byte was `Y` and current calculated IV byte is V we just need to send first byte to be `X^Y^V`.

Keep in mind that we need to have enough padding to shift whole flag to the left, so using just 1 block we will only recover up to 16 characters of the flag.

We were too lazy to check how the IV flips when it overflows 0xff so we just don't care and run again.
The charset is relatively small, so we just need to hit initial IV which is not too high.

```python
import string

from crypto_commons.generic import bytes_to_long
from crypto_commons.netcat.netcat_commons import nc, send, receive_until


def hexdecode(resp):
    if len(resp) % 2 == 1:
        resp = '0' + resp
    return resp.decode("hex")


def tohex(x):
    return hex(x).replace("0x", '')


def main():
    host = "crypto.utctf.live"
    port = 4355
    s = nc(host, port)
    charset = '_~!@#$%^&*(){}' + string.digits + string.ascii_letters
    known = ''
    for block_no in range(1, 5):
        hexknown = ''.join([tohex(ord(c)) for c in known])
        for secret in range(15):
            pad_length = 16 * (block_no - 1) + 15 - len(known)
            payload = 'AA' * pad_length
            send(s, payload)
            resp = receive_until(s, '\n').strip()
            pattern = resp[block_no * 32:(block_no + 1) * 32]
            print('pattern we want to find', pattern)
            initial_iv = bytes_to_long(hexdecode(resp)[0])
            for test in charset:
                x = hexdecode(resp)
                next_prefix = tohex(0xff & (0xaa ^ initial_iv ^ (bytes_to_long(x[0]) + 1)))
                test_payload = next_prefix + payload[2:] + hexknown + tohex(ord(test))
                send(s, test_payload)
                resp = receive_until(s, '\n').strip()
                if pattern in resp:
                    known += test
                    hexknown = ''.join([tohex(ord(c)) for c in known])
                    break
            print(known)


main()
```

And after a moment we get: `utflag{initialization_vectors_not_random}`
