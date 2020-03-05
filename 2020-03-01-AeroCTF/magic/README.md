# Magic 1 (crypto, 205p, 44 solved)

In the challenge we get [source code](task.py) and [data](output.txt).

The code is a quite simple stream cipher.
The interesting part is:

```python
    def create(cls, source: np.ndarray) -> 'Cipher':
        assert len(set(source.shape)) == 1
        line = source.reshape(-1)
        assert len(line) == len(set(line) & set(range(len(line))))
        keys = set(map(sum, chain.from_iterable((*s, np.diag(s)) for s in [source, source.T])))
        assert len(keys) == 1
        key = int(keys.pop())
        return cls(key, key % len(line))
```

This basically creates the `key` value which turned into bytes provides the keystream.
It might seem a bit complex, but in reality this function simply checks if provided `source` numpy array is a `magic square`.

`line = source.reshape(-1)` flattens the matrix into a single list and `assert len(line) == len(set(line) & set(range(len(line))))` checks if this list contains all numbers `0..n`.
Then `set(map(sum, chain.from_iterable((*s, np.diag(s)) for s in [source, source.T])))` makes a set of sums along all vertical, horizontal and diagonals of the matrix, and then it's checked if set contains only a single element.

The `key` value from which the keystream is derived is the magic number of the square, so the sum.

What we know in the task is encrypted flag and also `c = key % len(line) = key % n**2`.

The magic sum of such magic square (which starts from 0 and not clasically from 1) is:

```
M = (n * (n**2 + 1)) / 2 - n = (n/2)*(n**2+1-2) = (n/2)*(n**2-1)
```

Since we know `c = M%n**2` we can do:

```python
c == M mod n**2 
c == (n/2)*(n**2-1) mod n**2
2*c == n*(-1) mod n**2 # x-1 mod x == -1 mod x 
2*c == (-n) mod n**2
2*c == (n**2-n) # -k mod x == x-k mod x
n**2 -n -2c mod n**2 == 0
```

Now we can solve this quadratic equation `n**2 -n -2c = 0` for `n`:

```python
a = 1
b = -1
c = -2 * canary
delta = b ** 2 - 4 * a * c
x1 = -b - gmpy2.isqrt(delta) / 2 * a
x2 = -b + gmpy2.isqrt(delta) / 2 * a
x = x1 if x1 > 0 else x2
```

With this we can recover the magic sum of the square `key = x * (x ** 2 - 1) / 2`.
Finally we can decrypt the flag `print(long_to_bytes(ct ^ key))` and we get `Aero{m4g1c_squ4r3_1s_just_4n_4nc13nt_puzzl3}`
