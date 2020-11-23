# Bit Flip 3 (crypto, 343p, 16 solved)

## Description

In the challenge we get [server code](task.py).
It's almost the same code as in Part 1 and 2 of this challenge.
Similarly to part 2 we don't know Bob's number here, and also the prime generation changes.

## Task analysis

The main difference between part 1 and part 3 is:

```python
  def gen_strong_prime(self):
    prime = self.rng.getbits(512)
    iter = 0
    strong_prime = 2*prime+1
    while not (prime % 5 == 4) or not is_prime(prime) or not is_prime(strong_prime):
      iter += 1
      prime = self.rng.getbits(512)
      strong_prime = 2*prime+1
    print("Generated after", iter, "iterations")
    return strong_prime
```

Instead of any prime, this time we generate a strong prime, so not only sha blocks have to form a prime but also `2*prime+1` has to be a prime.

Similarly to part 2 we also don't know Bob's number, so we can't easily compute shared secret, and we need some trick.

## Vulnerability

The issue with the code is in place which not relevant in part 1 at all:

```python
cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
```

Specifically the part: `long_to_bytes(alice.shared, 16)[:16]`

Second parameter of `long_to_bytes` specifies the size of output blocks of bytes.
If you specify that you want `16 byte blocks` the function will generate zero-padding to return full blocks.

This is very interesting because AES key is taken from `first 16 bytes`.
This means that if such zero-padding is applied, then AES key will, at least partially, be constructed from this padding.

Notice:

```python
print(long_to_bytes(2 ** 512 + 1, 16)[:16].encode("hex"))
```

This returns `1` simply because we have 513 bits and therefore a full padding block is added!

This is not possible to apply in Part 2 of the challenge, becauses the prime is always 512 bits, but here the `strong prime` does `2*prime+1` which means that if the original `prime` had 512 bits, we will get 513 bit strong prime.
It's 50% chance to get such value, since we only need first of those 512 bits to be 1.

## Solution

### Long prime

First we need to generate a seed for a 512 bit prime:

```python
def prime_gen():
    while 1:
        alice_seed = os.urandom(32)
        alice = DiffieHellman(alice_seed)
        x = len(hex(alice.prime).replace("0x", "").replace("L", ""))
        print(x, alice_seed.encode("hex"))
        if x > 128:
            alice.set_other(random.randint(2 ** 63, 2 ** 64))
            print(long_to_bytes(alice.shared, 16)[:16].encode("hex"))
            break


prime_gen()
```

This way we get for example `f518d60deba9327df0b1c4681b64236e1554ab733c4e66c2c93a8837cc4c30eb`.
The generation takes a while, but we should't need more than a couple of iterations here.

### Zeroed secret

Just long prime is not yet enough.
Now we need the shared secret to also be above 512 bits.
Fortunately we can just change Bob's number as many times as we want until we get proper secret.
Again, this shouldn't take very long.

### Solver

We run exactly the same code as we did for Part 1.
The only difference is that for final round, we bitflip the seed to our target, and try to decrypt the flag assuming the shared secret had been mostly zeroed.
If this fails, we repeat:

```python
def final_round(s, seed, target_seed):
    while True:
        receive_until_match(s, 'bit-flip str')
        receive_until(s, "\n")
        send(s, b64e(long_to_bytes(int(seed, 2) ^ target_seed)))
        receive_until(s, "\n")  # generated after
        iv = b64d(receive_until(s, "\n"))
        enc_flag = b64d(receive_until(s, "\n"))
        for key in range(8):
            cipher = AES.new(long_to_bytes(key, 16)[:16], AES.MODE_CBC, IV=iv)
            flag = cipher.decrypt(enc_flag)
            if 'DrgnS' in flag:
                print(flag)
                return
```

It takes a while this time to recover the seed, because the `strong_prime` takes forever on the server, but eventually we get: `DrgnS{C0nst_A3S_K3y_1111111111111!}`

Complete solver [here](stage3.py)
