# secret-reverse (re, 365p, 20 solved)

## Description

```
There is a secret message hidden in this binar.

Encoded_message = 46004746409548141804243297904243125193404843946697460795444349

Find the message!

Flag format: ctf{sha256(original_message)}
```

In the task we get a [binary](rev_secret_secret).

## Task analysis

Running the binary with strace shows that it's trying to open `messages.txt` and read from it.
Once we create this file, for some inputs binary will return long number as result.

The code itself looks complex, so we're not going to analyse it much.
One useful thing noticed was that after reading from the input file the binary replaces `_` for `x` before running.

It seems charset is very limited and it mostly lowercase characters and numbers.

### Linear correlation and prefix matching

It's clear that longer input == longer output, but it also becomes clear very quickly that output has a very nice property: see what happens if we send realated inputs.

First it seems prefix always gets encrypted the same:

```
aaaa -> Encoded:  7444947
aabb -> Encoded:  744475
aacc -> Encoded:  7444748
```

While same pair at different position encrypts differently, but prefix property still holds for longer inputs:

```
aaaa ->     Encoded:  7444947
aaaaaa ->   Encoded:  74449479394
aaaaaaaa -> Encoded:  74449479394393
```

Finally, it seems given pair at given position always encrypts to the same value.

```
bbaa -> Encoded:  40474947
ccaa -> Encoded:  40464947
ddaa -> Encoded:    764947
```

## Solution

It is clear that we should be able to brute-force the flag by prefix matching, using 2 characters as input.
We simply check `aa, ab, ac, ad,..., ba, bb,...,zz` and try to match the output to the output we have:

```python
import codecs
import re
import string
import subprocess


def matched(target, encoded):
    res = 0
    for i in range(len(encoded)):
        if target[i] == encoded[i]:
            res += 1
        else:
            return res
    return res


def main():
    target = '46004746409548141804243297904243125193404843946697460795444349'
    known = ''
    charset = string.ascii_lowercase + string.digits
    best = 0, ''
    for i in range(10):
        for a in charset:
            for b in charset:
                test = known + a + b
                print('testing', test)
                with codecs.open("message.txt", 'wb') as data_file:
                    data_file.write(test)
                try:
                    res = subprocess.check_output("./rev_secret_secret.o")
                except subprocess.CalledProcessError:
                    continue
                encoded = re.findall("\d+", res)
                if len(encoded) > 0:
                    score = matched(target, encoded[0])
                    if score > best[0]:
                        best = score, test
        print('best', best)
        known = best[1]


main()
```

### Guessing the right flag

What we get is not perfect.
Apparently this was not very well tested and flag is not unique.
We have input which matches the target: `yessiiamxaxcriminallmastermindxbeaware`

We know from the beginning that there was replacing of `_` to `x` so we have: `yessiiam_a_criminallmastermind_beaware`.

Still not good enough :( But from here we can just guess: `yes_i_am_a_criminal_mastermind_beaware` and it matched the target as well and validated as the flag.
What confused us here was `beaware` which is some mix between `be aware` and `beware` and we were trying to somehow `fix` this...

Flag: `ctf{9b9972e4d59d0360b5f1b80a5bbd76c05d75df5b636576710a6271c668a10ac5}`
