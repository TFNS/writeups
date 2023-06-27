# AES Observed (crypto, 6 solves, 370p)

## Introduction

This was one of the sloppiest challenges on the CTF.
The idea was interesting, but it was done in a very unclear and unrealistic way.

We get from the server a bunch of plaintext values and a voltage measurement done "after sbox"

## Task analysis

The idea behind the solution is related to a "side channel" information leak and the assumption that the more `1` bits are to be set for some value, the more voltage drain is detected.

Issues with the task:

1. The first issue with the task is that it doesn't specify "which" sbox lookup we get. For AES-128 there are 10 rounds after all. We can guess that it most likely means the first sbox lookup, right after plaintext is XORed with a round key.
2. Second issue is that for a single block there are 16 sbox lookups (one per byte), so what exactly is the value we got?
3. Another issue is that we have 2 blocks, and first round of first block is done at completely different time than first round of second block, so again: what is the voltage value we're looking at?
4. One more issue was that it's unclear if the datasets are consistent between connections - essentially can we pull multiple datasets from the server, or do we have to work with just a single set.
5. Last problem is that we have some "plaintext" values, but it's unclear if those plaintexts were actually hex-strings, or we just got them as hex-encoded

As a result we have to make lost of "assumptions" to solve the task.
We essentially make assumptions necessary for this task to be solvable.

## Solution

The solution is based on the assumption that the number of `1` bits in `sbox[plaintext[i]^round_key[i]]` is correlated with the voltage value we have.
The higher the voltage, the more `1` we should have.
We know the `sbox` lookup table and we know the plaintext, so we can brute-force the value of `round key` byte by byte, picking the value which gives the best correlation when checked over multiple datasets.

The correlation calculation we stole from some blogpost.
The idea is that for each guess we split the datasets into 2 groups - with less than 4 bits set, and with more or equal to 4 bits.
Then we compute mean voltage for both groups and look for biggest difference between those.
So we want to pick the key byte such that those 2 groups are as far apart as possible:

```python
def solve(data):
    flag = ''
    for block in range(2):
        for byte in range(16):
            diffs = {}
            maximum = 0
            best = 0
            for guess in range(256):
                group1 = []
                group2 = []
                for line in data:
                    pt, v = line.split('\t')
                    b = binascii.unhexlify(pt.strip()[block * 32:block * 32 + 32])[byte]
                    hw = hamming(Sbox[b ^ guess])
                    if hw < 4:
                        group1.append(float(v))
                    else:
                        group2.append(float(v))
                g1_avg = np.mean(group1)
                g2_avg = np.mean(group2)
                diffs[guess] = np.abs(g1_avg - g2_avg)

                if diffs[guess] > maximum:
                    maximum = diffs[guess]
                    best = guess
            flag += chr(best)
            print(flag)
            print(byte, best)
    print(flag)
```

We need to pull multiple datasets from the server to get a clear enough results to recover the flag: `p4{Oscilloscopes? Still_matter!}`

Notice that we got different values for the round key for first and second block, which is completely wrong and not how AES works at all...
