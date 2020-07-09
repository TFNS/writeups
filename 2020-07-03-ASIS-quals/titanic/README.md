# Titanic (ppc, 128p, 34 solved)

## Description

In the task we connect to a server which (afer PoW) shows the problem description:

```
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

+ welcome to JPS challenge, its about just printable strings! the number  +
+ n = 114800724110444 gets converted to the printable `hi all', in each   +
+ round find the suitable integer with given property caring about the    +
+ timeout of the submit of solution! all printable = string.printable  :) +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
|
 whats the nearest number to 1367141302107188991138 that gets converted to the printable string?
```

The goal is to find closest number which converted to bytes will be printable.

## Solution

### Native solver for tests

We start off by making a naive solver so we can later check against it:

```python
def reference_solver(number):
    v = number
    while True:
        if is_printable(long_to_bytes(v)):
            high = v
            break
        else:
            v += 1
    v = number
    while True:
        if is_printable(long_to_bytes(v)):
            low = v
            break
        else:
            v -= 1
    if abs(low - number) < abs(high - number):
        return low
    else:
        return high
```

If you play around you notice pretty obvious regularity: every payload ends with either `0x09` or `0x7e`. 
This is pretty clear, if we at some point `lowered` a higher byte, then we want all lower bytes to be as high as possible, hence `0x7e`, and conversly if you at some point `raised` some higher byte, then we want all lower bytes to be as small as possible, hence `0x09`.

### Real solver

Mentioned regularity brings us to the actual solution.
It's clear that once we find position we want to modify, everything downstream from that point will be just `0x09` or `0x7e`.
It might seem that we just need to find a first non-printable byte, but this is in fact not a correct idea.

A couter-example would be `0x4FD9` where first byte is printable, but in fact it's better to modify this byte and not the next one.

But we assumed that in this case, maybe it's enough to just check 2 bytes? :)

We used the naive solver to generate mapping between 2 bytes block and the best result for that configuration.
Just in case we also generated such mapping for a single byte (for the corner case where only last byte is non-printable) and run:

```python
def solve(number):
    hexes = clean_hex(number).replace("0x", "").replace("L", "")
    if len(hexes) % 2 == 1:
        hexes = '0' + hexes
    chunks = chunk(hexes, 2)
    res = ''
    lowest = '09'
    highest = '7e'
    for i in range(len(chunks) - 1):
        c = "".join(chunks[i:i + 2])
        if c != hexmapping[c]:
            missing = len(chunks) - i - 2
            res += hexmapping[c]
            if int(c, 16) < int(hexmapping[c], 16):
                res += (lowest * missing)
            else:
                res += (highest * missing)
            break
        else:
            res += chunks[i]
    if len(res) / 2 < len(chunks):
        res += mapping_small[chunks[-1]]
    return int(res, 16)
```

This is not perfect, but it immediately can pass lots of stages!
Fortunately there are not that many stages and we can run this a couple of times until we get lucky -> `ASIS{jus7_simpl3_and_w4rmuP__PPC__ch41LEn93}`
