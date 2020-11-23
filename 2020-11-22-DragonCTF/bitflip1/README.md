# Bit Flip 1 (crypto, 155p, 84 solved)

## Description

In the challenge we get [server code](task.py).

## Task analysis

The task implements a simple Diffie-Hellman key exchange between 2 parties.
Prime is 512 bit and secrets are both 64 bits long.

Seed from which the `Alice` parameters are derived (prime and secret) is random, but we can XOR it with our own payload.
We can do that as many times as we want, and the seed is the same for the whole connection.

Seed for `Bob` is randomly selected each round.

### RNG

Random Number generator is using `sha256` to get 256 bits blocks.
Initially it hashes the seed, and then it repeats with `seed+1`, `seed+2` etc if more bytes are needed.

```python
  def more_bytes(self):
    self.generated += hashlib.sha256(self.seed).digest()
    self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
    self.num += 256
```

This `+1` business is important, because it means that if we were to `flip` last bit of the seed from `0` to `1` we would basically just `skip` one block of the RNG!

### DH parameters

Alice DH intitialization follows:

```python
  def gen_prime(self):
    prime = self.rng.getbits(512)
    iter = 0
    while not is_prime(prime):
      iter += 1
      prime = self.rng.getbits(512)
    print("Generated after", iter, "iterations")
    return prime

  def __init__(self, seed, prime=None):
    self.rng = Rng(seed)
    if prime is None:
      prime = self.gen_prime()

    self.prime = prime
    self.my_secret = self.rng.getbits()
    self.my_number = pow(5, self.my_secret, prime)
    self.shared = 1337
```

So first 512 bits (`sha256(seed)` and `sha256(seed+1)` are used as candiate prime.
If it's not prime, another 512 bit block is generated.
Once prime is found server tells us how many iterations it took.
Each iteration consumes 2 sha blocks and bumps the `+k` on the seed by 2.

Finally next 64 bits are used as secret.

## Solution

### General idea

As was remarked before, we have a very interesting oracle here: bit-flipping last bits of seed allows us to skip some of the `blocks`, and since we know the number of iterations it took to find a prime, we can also see the effect of this skipping.

Specifically if we could flip `seed` to `seed+2`, we basically `skip` one iteration on the prime generation.
And since we know the number of those iterations, we can be sure about this.

Imagine that we know that suffix of the seed is `?1010`, and we want to know `?`.
Let's change the seed to `?0000` and check number of iterations.
Then let's bitflip seed to become `(~?)1110` and again check number of iterations (notice: we can do the negation of `?` by sending bit `1` for XOR).

Notice what happens depending on value of `?` in the second payload:

- If `? == 1` then when we add `2` to `(~?)1110` we get `10000`
- If `? == 0` then when we add `2` to `(~?)1110` we get `(~X)00000`

Notice that in the first case, we arrive at exactly the same scenario as when we flipped the seed to `?0000` by sending known suffix as XOR payload.

This means that if number of iterations dropped by exactly `1` we know the `?` bit is `1`.
If the number of iterations randomly changes, we know the bit was `0`.


We can verify this with a simple sanity check:

```python
def sanity():
    s = 0b10101010
    known_suffix = '1010'
    zero_payload = s ^ int(known_suffix, 2)
    one_payload = s ^ int('1' + known_suffix[:-1] + '0', 2)
    DiffieHellman(long_to_bytes(zero_payload, 32))
    DiffieHellman(long_to_bytes(one_payload, 32))

    known_suffix = '01010'
    zero_payload = s ^ int(known_suffix, 2)
    one_payload = s ^ int('1' + known_suffix[:-1].replace('1', 'x').replace('0', '1').replace('x', '0') + '0', 2)
    DiffieHellman(long_to_bytes(zero_payload, 32))
    DiffieHellman(long_to_bytes(one_payload, 32))

sanity()
```

In first case we're guessing `0` and number of iterations gets random.
In second case we're guessing `1` and we get exactly one iteration more, as expected.

### Solver

We can now plug this in to the communcation code, and recover the seed:
```python
def get_iterations(s, msg):
    send(s, b64e(msg))
    receive_until_match(s, "Generated after ")
    count = int(receive_until(s, "\n").split(' ')[0].strip())
    return count


def round(s, suffix=''):
    all_1s = suffix.replace('1', 'x').replace('0', '1').replace('x', '0')
    all_1s = '1' + all_1s[:-1] + '0'
    count_all_0s = get_iterations(s, long_to_bytes(int(suffix, 2)))
    count_all_1s = get_iterations(s, long_to_bytes(int(all_1s, 2)))
    print('sub', count_all_1s - count_all_0s)
    if count_all_1s - count_all_0s == 1:
        return '1'
    else:
        return '0'


def main():
    port = 1337
    host = "bitflip1.hackable.software"
    s = nc(host, port)
    print(receive_until(s, "\n"))
    send(s, raw_input(">"))  # PoW
    suffix = '0'
    while len(suffix) < 128:
        print('suffix is', suffix)
        print(receive_until(s, "\n"))
        bit = round(s, suffix=suffix)
        suffix = bit + suffix
    seed = suffix
    print('Seed', seed)
    s.close()
```

Once we have the seed we can just grab `bobs number` from the server and decrypt the flag:

```python
def final_round(s, seed):
    receive_until_match(s, "bob number")
    send(s, b64e(b'\x00'))
    receive_until_match(s, "bob number")
    bob_no = int(receive_until(s, "\n").strip())
    alice = DiffieHellman(long_to_bytes(int(seed, 2)))
    alice.set_other(bob_no)
    print('Shared:', alice.shared)
    iv = b64d(receive_until(s, "\n"))
    cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
    enc_flag = b64d(receive_until(s, "\n"))
    print(cipher.decrypt(enc_flag))
```

And we get: `DrgnS{T1min9_4ttack_f0r_k3y_generation}`

Complete solver [here](stage1.py)