# SHArky (crypto, 231p, 38 solved)

## Description

In the task we get [challenge code](challenge.py) and [modified sha256](sha256.py).
We can connect to remote challenge server, it will provide us with keyed hash for known message `MSG = b'Encoded with random keys'`, and we need to provide the secret keys to get back a flag.

## Code analysis

### Main

From the main we know:

- There are 8 secret keys
- Each keys is 4 bytes long, taken from urandom
- Hashed message is known
- There are no vulnerabilities here

### SHA code

Since we're supposed to recover round keys, let's try to see where they are used, and can be invert operations leading to them.

Last step of hash is:

```python
  def sha256(self, m, round_keys = None):
    m_padded = self.padding(m)
    state = self.sha256_raw(m_padded, round_keys)
    return struct.pack('>8L', *state)
```

This part is trivially invertible, we just need to unpack the output hash value with the same format, and we can proceed to `sha256_raw`:

```python
state = struct.unpack('>8L', digest)
```

Next function is:

```python
  def sha256_raw(self, m, round_keys = None):
    if len(m) % 64 != 0:
      raise ValueError('m must be a multiple of 64 bytes')
    state = self.h
    for i in range(0, len(m), 64):
      block = m[i:i + 64]
      w = self.compute_w(block)
      s = self.compression(state, w, round_keys)
      state = [(x + y) & 0xffffffff for x, y in zip(state, s)]
    return state
```

We don't care about length check, since input is padded.
Then we have a loop over 64-byte input blocks.
We don't care about that either, since our input is short and there will only be a single block.
This means we only care about:

```python
state = self.h
w = self.compute_w(block)
s = self.compression(state, w, round_keys)
state = [(x + y) & 0xffffffff for x, y in zip(state, s)]
```

Note that `self.h` - initial hash state - is constant, and `compute_w` uses only hash input, so for us it's also basically constant.
Then the final step of combining new state `s` and result of `compression` function is just addition, so we can invert it easily.
We just need:

```python
sha = sha256.SHA256()
w = sha.compute_w(sha.padding(MSG))
raw_state = [((x - y) + 0xffffffff + 1) & 0xffffffff for x, y in zip(state, sha.h)]
```

This way we get back the result of `self.compression(state, w, round_keys)`.
We finally reached code which uses the `round keys`.

Compression function is basically just:

```python
for i in range(64):
    state = self.compression_step(state, round_keys[i], w[i])
```

And compression_step:

```python
def compression_step(self, state, k_i, w_i):
    a, b, c, d, e, f, g, h = state
    s1 = self.rotate_right(e, 6) ^ self.rotate_right(e, 11) ^ self.rotate_right(e, 25)
    ch = (e & f) ^ (~e & g)
    tmp1 = (h + s1 + ch + k_i + w_i) & 0xffffffff
    s0 = self.rotate_right(a, 2) ^ self.rotate_right(a, 13) ^ self.rotate_right(a, 22)
    maj = (a & b) ^ (a & c) ^ (b & c)
    tmp2 = (tmp1 + s0 + maj) & 0xffffffff
    tmp3 = (d + tmp1) & 0xffffffff
    return (tmp2, a, b, c, tmp3, e, f, g)
```

#### Invert compression steps for known keys

Note that we know all `w_i` values, we know the final `state` and we know all `k_i` apart from 8 first ones.
We want to `invert` the `compression_step` function, and looking at the operations there it's pretty simple.
6 out of 8 variables don't change at all, so we can recover them immediately.
This leaves us with recovering `h` and `d`.

Recovering `d` is pretty straightforward:

```
tmp2 = (tmp1 + s0 + maj) & 0xffffffff
tmp3 = (d + tmp1) & 0xffffffff
```

And we know `tmp2` and `tmp3` so:

```
tmp1 = (tmp2 - (s0 + maj)) & 0xffffffff
d = (tmp3 - tmp1) & 0xffffffff
```

There is only one equation involving `h`:
```
tmp1 = (h + s1 + ch + k_i + w_i) & 0xffffffff
```

We know `tmp2`, therefore:
```
s1 = self.rotate_right(e, 6) ^ self.rotate_right(e, 11) ^ self.rotate_right(e, 25)
ch = (e & f) ^ (~e & g)
s0 = self.rotate_right(a, 2) ^ self.rotate_right(a, 13) ^ self.rotate_right(a, 22)

tmp1 = (tmp2 - (s0 + maj)) & 0xffffffff
h = (tmp1 - (k_i + s1 + ch + w_i)) & 0xffffffff
```

`s2`, `ch`, and `s0` are based on parameters we know, so the only issue is that recovering `h` requires us to know `k_i`.

This means we can invert all upper rounds, because all but 8 low `k_i` values are secret, rest are constant:

```python
def invert_step(state, w_i, k_i):
    tmp2, a, b, c, tmp3, e, f, g = state
    maj = (a & b) ^ (a & c) ^ (b & c)
    s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)
    s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)
    tmp1 = (tmp2 - (s0 + maj)) & 0xffffffff
    d = (tmp3 - tmp1) & 0xffffffff
    ch = (e & f) ^ (~e & g)
    h = (tmp1 - (k_i + s1 + ch + w_i)) & 0xffffffff
    return a, b, c, d, e, f, g, h
```

We can run this as:

```python
    original_keys = sha.k[:]
    for i in range(1, 65 - secret_keys):
        state = invert_step(state, w[-i], original_keys[-i])
```

And we reach `state` value after `compression_step` was called 8 times, with secret keys, on the input.

#### Recovering missing keys

Notice that we could easily recover `k_i` value, assuming we know `h` value, simply because:

```
h = (tmp1 - (k_i + s1 + ch + w_i)) & 0xffffffff
```
and thus
```
k_i = (tmp1 - (h + s1 + ch + w_i)) & 0xffffffff
```

Otherwise we just know `h+k_i` and we have no means of `splitting` this sum further.

However, it's important to notice that we know initial state - `sha.h`.
It is interesting to look at how those values are propagated through the 8 rounds with secret keys.

Consider: what would happen if we set `k_i` in last secret round to `0` and try to invert?

1. After first round our computed `h` value is `h = (tmp1 - (0 + s1 + ch + w_i)) & 0xffffffff` instead of `h = (tmp1 - (k_i + s1 + ch + w_i)) & 0xffffffff` so it's off by exactly `-k_i`
2. After second round this value is just shifted left
3. After third round this value is just shifted left
4. After fourth round the value is modified, but just by constant subtraction
5. After fifth round value is just shifted left
6. After sixth round value is just shifted left
7. After seventh round value is just shifted left

Pretty much the value would be smaller by exactly `-real_k_i`, and then it would be just shifted to the end.

This means we could run `invert_step` 8 times, using `0` as key value, and then just compare the `a` value we reach with the real `a` value from `sha.h` state, to know what was `-real_k_i` value.

Once we recover the last `k_i` we can invert this round properly, and then perform similar attack for bottom 7 rounds, and compare second value from initial state etc:

```python
f_state = state
for i in range(7, -1, -1):
    for j in range(i + 1):
        state = invert_step(state, 0, w[i - j])
    real_key = state[7 - i] - sha.h[7 - i]
    keys.append(real_key)

    state = f_state
    for idx, k in enumerate(keys):
        state = invert_step(state, k, w[7 - idx])
```

This way we can recover all missing keys (in inverted order).

## Solver

We can collect all of those pieces to a proper solver:

```python
def recover_keys(digest):
    state = struct.unpack('>8L', digest)
    sha = sha256.SHA256()
    w = sha.compute_w(sha.padding(MSG))
    raw_state = [((x - y) + 0xffffffff + 1) & 0xffffffff for x, y in zip(state, sha.h)]
    secret_keys = 8
    keys = []
    state = raw_state
    original_keys = sha.k[:]
    for i in range(1, 65 - secret_keys):
        state = invert_step(state, w[-i], original_keys[-i])

    f_state = state
    for i in range(7, -1, -1):
        for j in range(i + 1):
            state = invert_step(state, 0, w[i - j])
        real_key = state[7 - i] - sha.h[7 - i]
        keys.append(real_key & 0xffffffff)

        state = f_state
        for idx, k in enumerate(keys):
            state = invert_step(state, k, w[7 - idx])
    return keys[::-1]
```

And we can use this with remote service:

```python
def main():
    port = 1337
    host = "sharky.2020.ctfcompetition.com"
    s = nc(host, port)
    digest = receive_until(s, b'\n')[12:-1]
    keys = recover_keys(binascii.unhexlify(digest))
    print(keys)
    result = [hex(key).replace("0x", "").encode() for key in keys]
    print(b','.join(result))
    send(s, b','.join(result))
    interactive(s)
```

To get the flag: `CTF{sHa_roUnD_k3Ys_caN_b3_r3vERseD}`
