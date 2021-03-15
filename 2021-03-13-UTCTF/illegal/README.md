# Illegal prime (crypto, 799p, 143 solved)

## Description

```
The NSA published the ciphertext from a one-time-pad. Since breaking one-time-pad is so easy, I did it for you.

To avoid legal trouble I can't tell you the key. On an unrelated note I found this really cool prime number ( https://en.wikipedia.org/wiki/Illegal_prime )
```

We get also:

```
c = 2f7f63b5e27343dcf750bf83fb4893fe3b20a87e81e6fb62c33d30

p = 56594044391339477686029513026021974392498922525513994709310909529135745009448534622250639333011770158535778535848522177601610597930145120019374953248865595853915254057748042248348224821499113613633807994411737092129239655022633988633736058693251230631716531822464530907151
```

## Task analysis

Task hints at `illegal prime` story, where binary representation of certain number could be treated as machine code with an exploit.

## Solution

If we do `print(long_to_bytes(p))` on the provided prime we get:

```
k = 5a0b05d9831438ac8561d2b0a42be1cf5613db21deb9a443e21c4d
```

Now that we have the key we can just unxor the flag:

```python
c = '2f7f63b5e27343dcf750bf83fb4893fe3b20a87e81e6fb62c33d30'.decode('hex')
print(xor_string(c, '5a0b05d9831438ac8561d2b0a42be1cf5613db21deb9a443e21c4d'.decode("hex")))
```

And get `utflag{pr1m3_cr1m3s____!!!}`
