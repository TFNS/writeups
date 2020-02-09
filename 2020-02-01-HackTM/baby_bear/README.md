# Baby bear (re, 442p, 36 solved)

In this challenge we, theoretically, get a binary to reverse.
Interestingly enough, it was much easier to solve is (similarly to Papa bear), without reversing anything at all.
`Every RE is black-box crypto if you're brave enough`.

The idea is that when you run the binary, it reads some random bytes from urandom, 
then performs some strange operations, and finally prints out binary string.

The goal is to guess those random bytes, and then on the server we will get the flag.

What we also get from the binary is the encrypted binary string for input we provide, even if it didn't match the expected one.

There is no special configuration for the binary, so the local one works the same as remote one.
It is also deterministic, so for given input, the output is always the same.

If we observe just the outputs, we can notice a very interesting property -> for given prefix of data, the output prefix is always the same.

For example if we use the binary to encrypt `ab`, `ac`, `ad`, `ae`... the first few bits are always the same.
This property holds for any length input!

This means we can easily brute-force the proper values byte-by-byte.
The idea is to encrypt `0x1`, `0x2`, ... `a`, `b`,`c`... and check for which byte the prefix of the output matches the most characters of the target ciphertext.
Once we find the first byte, we start doing the same for 2 bytes, then for 3 up until we recover all of them.

We can use the local binary to make it faster, if we overcome the twist that the binary is writing outputs to stdin instead of stdout.

```python
from crypto_commons.netcat.netcat_commons import nc, receive_until_match, receive_until, send, interactive


def prefix_len(a, b):
    counter = 0
    for x, y in zip(a, b):
        if x == y:
            counter += 1
        else:
            return counter


def recover_input(task):
    prefix = ""
    max = 0
    best = '\0'
    for i in range(10):
        for c in range(256):
            host = "127.0.0.1"
            port = 12345
            s = nc(host, port)
            receive_until_match(s, "What do you say\? ")
            send(s, prefix + chr(c))
            response = receive_until(s, "\n").strip()
            len = prefix_len(task, response)
            if len > max:
                max = len
                best = chr(c)
        prefix += best
        max = 0
        print(prefix.encode("hex"))
    return prefix


def main():
    host = "138.68.67.161"
    port = 20005
    s = nc(host, port)
    receive_until_match(s, "Baby bear says: ")
    task = receive_until(s, "\n")
    receive_until_match(s, "What do you say\? ")
    print('target', task)
    response = recover_input(task)
    s.sendall(response)
    interactive(s)


main()
```

With this after few seconds we get the right string and flag from the server `HackTM{Oh~n0~G0ld!lOcK$~wh4t~hAV3~U~doNE??}`
 
