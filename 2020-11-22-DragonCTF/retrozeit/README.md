# RetroZeit (re, 197p, 56 solved)

## Description

In the task we get a [amiga binary](retrozeit) to reverse engineer.

## Binary analysis

We initially just loaded this into Ghidra as 68000 CPU, but this wasn't ideal because the memory mapping was all wrong.
The code was decompiled mostly correctly, but references to data were not.
For a moment we thought about adding the mapping by hand, but we found https://github.com/lab313ru/ghidra_amiga_ldr

We can now load the binary with this plugin active and we get much nicer output immediately.

### main

Main is located at `0021f4de` and the important part is:

```c
  check_result = check_flag();
  if (check_result == '\0') {
    print("Calculating the flag",&local_158,0x15);
    FUN_0021fef0(auStack323,0x6b);
    local_24 = (undefined *)((int)local_24 + 1);
    if (3 < (int)local_24) {
      local_24 = (undefined *)0x0;
    }
    i = (undefined *)0x0;
    while ((int)i < (int)local_24) {
      print(&local_158,".");
      i = i + 1;
    }
    version = i;
    FUN_0021f182(&local_158);
    retry_shuffle_flag();
    FUN_0021f104(local_8,100);
  }
  else {
    local_158 = 0x46;
    local_157 = 0x6c;
    local_156 = 0x61;
    local_155 = 0x67;
    local_154 = 0x3a;
    local_153 = 0x20;
    local_152 = 0;
    FUN_0021fef0(auStack337,0x79);
    version = &local_152;
    decrypt(version);
    FUN_0021f182(&local_158);
    local_ce = '\0';
  }
```

If we drop all unnecessary stuff we have just:

```c
  check_result = check_flag();
  if (check_result == '\0') {
    retry_shuffle_flag();
  }
  else {
    decrypt(enc_ch);
  }
```

This is all in a long loop.
So there is some special check done, and if it failed the `retry` function is called and if it passes there is some decryption done.

### decrypt

Let's first look at `decrypt` at `0021f430`:

```c
  byte buffer [100];
  
  FUN_0021fef0(buffer,100);
  i = 0;
  while (i < 0x27) {
    buffer[i] = ~(&enc_ch)[i] ^ (byte)i;
    i = i + 1;
  }
```

This is rather simple, just negate `k-th` byte and XOR with `k`.
Notice we're decrypting contents of `enc_ch` array.

In python this is:

```python
def decrypt(enc_ch):
    out = b""
    for i, c in enumerate(enc_ch):
        a = ord(c)
        a = (~a) & 0xff
        a = a ^ i
        out += chr(a & 0xFF)
    return out
```

### retry (shuffle)

Next interesting function is `retry` which is pretty much a random shuffle:

```c
  i = 0;
  while (i < 0x32) {
    r = rand();
    a = modulo(r,0x27);
    r = rand();
    b = modulo(r,0x27);
    if (a != b) {
      a_idx = (&enc_idx)[a];
      a_chr = (&enc_ch)[a];
      (&enc_idx)[a] = (&enc_idx)[b];
      (&enc_ch)[a] = (&enc_ch)[b];
      (&enc_idx)[b] = a_idx;
      (&enc_ch)[b] = a_chr;
    }
    i = i + 1;
  }
```

We get two random indices `a` and `b` and swap corresponding elements of two arrays, the `enc_ch` we've seen in `decrypt` but also `enc_idx`.
The swap is identical, so both arrays are shuffled the same way.
`rand` here is just standard libc `((seed * 1103515245) + 12345) & 0x7fffffff`

We won't really need this function.
The idea of the task is that after enough shuffles you get some special order which passes the `check_flag` and decrypts the real flag.

### check flag

Now it's time for the only important function here, `check_flag` at `0021f258`:

```c
  previous = enc_idx;
  retval = in_D0 & 0xffffff00;
  if ((enc_idx & 1) == 0) {
    retval = 0;
    i = 2;
    while (i < 0x27) {
      if (previous <= (&enc_idx)[i]) {
        return i & 0xffffff00;
      }
      previous = (&enc_idx)[i];
      retval = i & 0xffffff00;
      if ((previous & 1) != 0) {
        return retval;
      }
      i = i + 2;
    }
    previous = enc_idx_p1;
    if (((enc_idx_p1 ^ 1) & 1) == 0) {
      j = 3;
      while (j < 0x27) {
        if ((&enc_idx)[j] <= previous) {
          return j & 0xffffff00;
        }
        previous = (&enc_idx)[j];
        if (((previous ^ 1) & 1) != 0) {
          return j & 0xffffff00;
        }
        j = j + 2;
      }
      retval = 1;
    }
  }
  return retval;
```

We have two separate loops here.
Frist one is starting at `2` and is jumping by `2`, so it's traversing all `even` elements of the `enc_idx` array.
Second is starting at `3` and also jumping by `2` so it's traversing all `odd` elements of `enc_idx` array.

In each of the loops we have 2 checks which have to pass, or the check is failed.

First check is `parity`.
For even we have:

```c
if ((previous & 1) != 0) {
    // fail
```

So even elements have to have LSB set to 0, so they need to be even.

For odd we have:

```
if (((previous ^ 1) & 1) != 0) {
    // fail
```

So it's the opposite, and we need to have elements with LSB set to 1, so they need to be odd.

Second check verifies `ordering of elements`.

For even we have:

```c
if (previous <= (&enc_idx)[i]) {
    // fail
```

So `next` element in array has to be smaller than previous element, otherwise it's just `descending order`.

For odd we have:

```c
if ((&enc_idx)[j] <= previous) {
    // fail
```

So `next` element has to be larger than previous, or simply `ascending order`.

We can reimplement this as:

```python
def check(enc_idx):
    previous = enc_idx[0]
    if is_even(previous):
        for i in range(2, len(enc_idx), 2):
            if previous <= enc_idx[i]:
                return 0
            previous = enc_idx[i]
            if not is_even(previous):
                return 0
    previous = enc_idx[1]
    if is_odd(previous):
        for i in range(3, len(enc_idx), 2):
            if enc_idx[i] <= previous:
                return 0
            previous = enc_idx[i]
            if not is_odd(previous):
                return 0
    return 1
```

## Solution

It's pretty clear that `enc_idx` shuffling which will pass the check is as follows:

- even elements are all even
- odd elements are all odd
- even elements are in descending order
- odd elements are in ascending order

This means:

```python
wanted = [None for _ in range(39)]
for i in range(0, 39, 2):
    wanted[i] = 38 - i
for i in range(1, 39, 2):
    wanted[i] = i
assert check(wanted) == 1
```

We can verify that this passes the `check` function.
Now we need to shuffle the `enc_ch` properly.

We first need to get the original values from the binary, but with proper memory mapping xrefs work fine:

```python
enc_chr = '8b 84 9a 9b 9a b1 d6 af 93 b2 81 8c 84 ab 9d 9c 8e b9 b0 d9 a8 a4 9c 81 85 a0 a6 b4 87 9a bb 92 96 ad 8c d7 b0 8d 97'.replace(" ", '').decode('hex')
idx = '16 0c 24 17 13 19 07 09 0e 23 05 01 18 21 0d 10 12 1f 1a 1e 22 00 0f 0b 08 15 11 02 1d 1c 26 03 04 25 14 20 06 1b 0a'.replace(' ', '').decode('hex')
enc_idx = [ord(c) for c in idx]
```

For that we simply need to create a mapping between `enc_idx` and `wanted`, because the same mapping can be applied to `enc_ch`:

```python
mapping = {i: enc_idx.index(x) for i, x in enumerate(wanted)}
```

We can verify that this mapping is valid by:

```python
shuffled = [enc_idx[mapping[i]] for i in range(39)]
assert check(shuffled) == 1
```

Now we just apply the mapping and call decrypt:

```python
payload = [enc_chr[mapping[i]] for i in range(39)]
print(decrypt(payload))
```

And we get `DrgnS{...YouCouldHaveJustWaitedYouKnow}`
