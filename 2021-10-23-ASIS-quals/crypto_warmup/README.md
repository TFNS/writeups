# Crypto warmup (crypto, 41p, 147 solved)

## Description

```
Recovering secrets is hard, but there are always some easy parts to do it!
```

## Task analysis

In the task we get [source code](Warmup.py) and [output](output.txt).
The encryption code is simple:

```python
def encrypt(msg, nbit):
    l, p = len(msg), getPrime(nbit)
    rstr = random_str(p - l)
    msg += rstr
    while True:
        s = getRandomNBitInteger(1024)
        if is_valid(s, p):
            break
    enc = msg[0]
    for i in range(p-1):
        enc += msg[pow(s, i, p)]
    return enc
```

First part is just adding padding to the flag, so that the output has exactly `p` bytes, where `p` is a random 15-bit prime.
Notice: from the output length we know `p`.

Then a random large integer `s` is selected and elements of the padded flag are shuffled, so that i-th element of the output corresponds to `pow(s, i, p)` element of padded flag.

There is a secret `is_valid` check in the code, but it most likely just makes sure there is no cycle when generating the shuffling permutation. Such cycle would mean some parts of the original message would not be present in output.

Our goal is to recover the shuffling order.
It's clear to see that we need to somehow learn values of `pow(s,i,p)`, but we don't know `s`.

## Solution

### Observations

To solve the challenge we will use 3 important things:

1. We know flag prefix `ASIS{`
2. We know that `(x^a mod p) * (x^b mod p) mod p == x^(a+b) mod p`, which means that if we know `s mod p` we can calculate any `s^i mod p`.
3. `p` is very small and we can easily bruteforce every value 0..p

### Solution overview

1. Let's assume we know `s mod p`, since we can easily just check every possible value 0..p-1
2. For known `s mod p` we can compute any `pow(s,i,p)` we want. 
3. We know that `I` was `msg[2]`, so if `pow(s,i,p)==2` then `enc[i]='I', because of how the shuffle works
4. Similar observation can be made for `msg[3]` and `S` (and possibly also for `{` and `msg[4]`)
5. We can easily find every index `i` such that `enc[i] == 'I'` and index `j` such that `enc[j]='S'`

Our solution will be as follows:

1. Bruteforce every possible `s mod p` 
2. For each value let's iterate over all possible idices `i` such that `enc[i] == 'I'`.
3. If we find a case where `pow(s,i,p) == 2` then we have a valid candidate for real `s mod p`. 
4. We can now test this value in similar way for `'S'`, so iterate over all possible indices `i` such that `enc[i] == 'S'` and look for `pow(s,i,p)==3`. If we find it, we can assume we got very strong candidate for `s mod p`.
5. We can proceed further with `{` in similar fashion.

Once we have candidate `s mod p` we can simply decrypt the flag, and look for the real one with:

```python
def decrypt(s, enc, p):
    recovered = ['?' for _ in range(p)]
    recovered[0] = 'A'
    for i in range(len(enc) - 1):
        index = pow(s, i, p)
        recovered[index] = enc[i + 1]
    return ''.join(recovered)
```

### Solver

```python
def main():
    enc = open("output.txt", 'rb').read().decode()
    p = len(enc)
    print('p', p)
    # mind i-1 because index enc[0] was set by hand, so it's all shifted
    a = [i - 1 for i, x in enumerate(enc) if x == 'I']
    b = [i - 1 for i, x in enumerate(enc) if x == 'S']
    c = [i - 1 for i, x in enumerate(enc) if x == '{']
    for s in range(0, p):
        # assume we know s%p
        for aa in a:
            if pow(s, aa, p) == 2:
                for bb in b:
                    if pow(s, bb, p) == 3:
                        for cc in c:
                            if pow(s, cc, p) == 4:
                                print('candidate s mod p', s)
                                print(decrypt(s, enc, p))


```

And we get only two possible flags, valid one being `ASIS{_how_d3CrYpt_Th1S_h0m3_m4dE_anD_wEird_CrYp70_5yST3M?!!!!!!}`
