# Hobbit (re, 525p, ? solved)

In the task we get a [kernel module](hobbit.ko) and a custom format [binary](chall.hbt).
We also get all the rest of necessary setup to run this via qemu.

The kernel module contains logic of loading the HOBBIT binaries.
Our initial approach was to reverse engineer the loader, since it's doing some machine code decoding process, and get the pure code from the binary.

This proved to be quite challenging, even more so if someone is not well versed in kernel functions.
The loading process seems to first decode the header and then rest of the binary, both using the same `The_Load_of_the_Rings` function, which in turn calls `wear_ring` function, which calls `pickup` and `adjust`.
The two last ones are the core - they perform lots of XORs on the binary payload.

We tried to re-implement them, but it didn't work, and without ability to debug the original loader it's hard to know where can be the mistake.

The second idea was to run this, debug qemu with gdb and break on the binary loading process, but this proved to be very complicated to perform.

Finally we tried the best approach for every RE task -> don't reverse it at all.
Instead we run qemu, start the hobbit binary (to make sure it's loaded in memory) and then dumped qemu memory with `gcore`.
We effectively swapped RE problem for a forensics one.

Now we have 512MB dump to analyze.
Fortunately the binary prints `FLAG:` when it starts so we can grep for this string in the memdump, and we find some nice part:

```
FLAG: .Correct!..Wrong!..]CW.SVR[{-.xhEn){zJz#fNr<Qa?xyV~3j40mv|
```

Sadly it seems the flag is not in plaintext, and there is nothing around in this memory region which would look like reasonable code.

But you all should know by now that `Every RE is blackbox crypto if you're brave enough!`

The hobbit binary was really small and here we have 64 bytes of pure data, so the idea is that the encryption of the flag can't be very complex, because it would simply not fit.

And we know the flag prefix, so we can do some tests, and already the first one is promising:

```python
data = ']CW\x14SVR[{-.xhEn){zJz#fNr<Qa?xyV~3j40mv|'
print(xor_string(data, "zer0pts{").encode('hex'))
```

We get `2726252423222120`.
It seems the flag simply is XORed with consecutive numbers.
We can just do:

```python
data = ']CW\x14SVR[{-.xhEn){zJz#fNr<Qa?xyV~3j40mv|'
key = map(chr, range(0x27, -1, -1))
print(xor_string(data, key))
```

And we recover: `zer0pts{d33ds_w1ll_n0t_b3_l3ss_v4l14nt}`
