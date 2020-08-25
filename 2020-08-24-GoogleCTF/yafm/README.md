# YAFM (crypto, 308p, 18 solved)

## Description

In the task we get access to [server code](server.py).
After connection we can:

1. Generate new RSA keypair and get public key
2. Get flag encrypted with last generated key

We can do that multiple times, although it's not really needed, unless you're very unlucky.

## Code analysis

The encryption itself is strong - it's even using OAEP and not textbook RSA.
The only strange part is prime generation, similarly as in `Chunk Norris`:

```python
def generate_prime(prime_len):
  bits_len = 180
  while True:
    bits = random.getrandbits(bits_len)
    idxs = random.sample(list(range(1, prime_len-2)), bits_len)
    p = 1 | 2**(prime_len - 1) | 2**(prime_len - 2)
    for i in range(bits_len):
      p += (bits >> i & 1)*2**idxs[i]
    if isPrime(p):
      return p
```

The logic is pretty simple:

1. Generate random 180 bits.
2. Generate random 180 unique values in range 0..prime_bitlen_we_want. Let's call those "target index"
3. Take bit value `random_bits[i]` and place it on `target_index[i]` bit of result

For example if our generated random bits are `101` and targets are [2,5,7] then result would be:
```
0 0 1 0 0 0 0 1 
```
because we placed bits `1` on position `2` and `7`.

Random 180 bits will have about 90 bits with value 1 and 90 bits with value 0, which means the result will have about 90 bits set to 1.

In the task we generate 1024 bit primes, and only about 90 bits will be set to 1!

## Solution

### Brute-force from low bits

We need to factor `n` into primes in order to solve the challenge.
Normally we would have exponentially many potential values to check, but here we know that we're only interested in 1024 bit numbers with ~90 bits set to 1.
We also know `n`, so we know the product.

Important thing to notice is that when multiplying values `p` and `q`, the low bits of the product are only dependent on low bits of `p` and low bits of `q`.
Higher bits can't influence them!

This means that low bits of `p*q` are the same as low bits of `p%2**k * q%2**k`.

Using this property, we could try to guess `k` low bits of `p` and `k` low bits of `q` and we can easily check if this guess could be true or not -> we just compare the product with `k+1` low bits of `n`.
If they match, then we have a valid candidates.

### Pruning candiates

Described approach works fine, but unfortunately it still can double the number of candiates on each level.
This will not scale past first few bits.

But we still have one property we didn't use - we know that primes we want have only a handful of `1` in binary representation.
We can sort the candidates, to have the ones with least 1s at the front, and we can drop the candidates with too many 1s:

```python
def order(candidates):
    return sorted(candidates, key=lambda (p, q): bin(p).count('1') + bin(q).count('1'))
```

We can't cut too early because it might happen that there are a few 1s in row, but other than that this approach should work.
Empirically `4096 * 8` was enough:

```python
def recover(n, bits):
    candidates = {(0, 0)}
    for bit in range(0, bits):
        print(bit)
        remainder = n % (2 ** (bit + 1))
        new_candidates = set()
        for potential_p, potential_q in candidates:
            # extend by 0 bit and by 1 bit on the left, so candidate 101 -> 0101 and 1101
            extended_p = potential_p, (1 << bit) + potential_p
            extended_q = potential_q, (1 << bit) + potential_q
            for p in extended_p:
                for q in extended_q:
                    if (q, p) not in new_candidates: # p,q and q,p is the same for us
                        if (p * q) % (2 ** (bit + 1)) == remainder:
                            new_candidates.add((p, q))
        candidates = order(list(new_candidates))[:4096 * 8]
    return candidates
```

We can try this function on some simple sanity check:

```python
def sanity():
    bits = 1024
    real_p = generate_prime(bits)
    real_q = generate_prime(bits)
    n = real_p * real_q
    print(bin(real_p))
    print(bin(real_q))
    
    candidates = recover(n, 100) # get bottom 100 bits
    bp = bin(real_p).replace("0b", "")
    for i, (p, q) in enumerate(candidates):
        if bp.endswith(bin(p).replace('0b', '')):
            print(i, 'OK p')
```

And it works just fine.
Even more, we can see that we got matching candidates at very low index numbers, which means our assumption of ordering candidates by the number of 1s was a valid strategy!

## Solution

Now we can just grab modulus from server and do:

```python
candidates = recover(n, 1024)
for (p, q) in candidates:
    if n % p == 0:
        print('p', p)
    if n % q == 0:
        print('q', q)
```

And then:

```python
    n = 18563827358136577465267394103137418511778836453237333252731089831985207993297377674711718126894282113110854542340506719124654577851501759992704484175930480370120399113587595921344145822564132345729782215786113357122128677650922656086908690722288872430249777009493240154973576987583399914901202308153498427130938926050425491294075497786411601951975080316448370370895093391031104920440122645440028847210538430981470643705518908648030244270003139925917177837911073147099211655799274365379543768564254067636571762109818165745315514000608571237824275911379421152555014254649239533933080848573120832533670490343832604147777L
    p = 134876365611179104890394041593217124534345124636535664306051910544674868766699030191642534080825704005800460003736048116292763217840538933794148323538135487601807559211215036931617439853337892259935734583398318586849717093267546491873502727956980320348991862002488168847934555860613714877474782224976801955841L
    q = 137635880637919053765890787229727728446512826746647121730690147695530725448539354803536002981961237876523522805087825719543597369579447287490208333401471646555458150340808952867992172140608307272704997799557876650898212752342239223742621220080359016764650648071916857003946984959679279595816405192413618143297L
    phi = (p - 1) * (q - 1)
    e = 65537L
    d = modinv(e, phi)
    ct = '83f237381b509803ea0546753032bd4d1f98dffe1326669ca2627735dd19fdb9fdbfea68ac7f67998b83f6eb7ff93d3c3807f014cbfb75e5f5160797f4a6ba1adc51ec8347e9d14b3ab726de21f01b696ae6434e77cca87cc070fd4d507f706e1fa1d70ad573d418b20adb94bb7d8a11e75e7974b95ecffbc452509c2867c56fc772bdbda706c768a243477e3389678c5a42d789f6dca68a65b36287e546940bef3bfd94dd3ad11cd831b1ef3036db369238bfefb00966a495687d45d4e76d56ad31cb4684bdcd42a67fe5ff111fc92adec8acd3b1c90ae2be262348279deeabfdaaf2fe9deeb615df4942662a50af459c14e0d5b5d3d4151cceaceda321a74c'.decode(
        "hex")
    key = RSA.construct((n, e, d))
    cipher = PKCS1_OAEP.new(key)
    print(cipher.decrypt(ct))
```

And we get: `CTF{l0w_entr0py_1s_alw4ys_4_n1ghtmar3_I_h4v3_sp0ken}`
