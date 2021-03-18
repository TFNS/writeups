# Sleeves (crypto, 990p, 34 solved)

## Description

```
I like putting numbers up my sleeves. To make sure I can fit a lot of them, I keep the numbers small.
```

We get challenge generation code:

```python
from challenge.eccrng import RNG
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

rng = RNG()
# I'll just test it out a few times first
print("r1 = %d" % rng.next())
print("r2 = %d" % rng.next())

r = str(rng.next())
aes_key = SHA256.new(r.encode('ascii')).digest()
cipher = AES.new(aes_key, AES.MODE_ECB)
print("ct = %s" % cipher.encrypt(b"????????????????????????????????????????").hex())
```

ECRG code:

```sage
from random import randint

class RNG:    
    def __init__(self):
        p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

        self.curve = EllipticCurve(GF(p), [-3,b])
        self.P = self.curve.lift_x(110498562485703529190272711232043142138878635567672718436939544261168672750412)
        self.Q = self.curve.lift_x(67399507399944999831532913043433949950487143475898523797536613673733894036166)
        self.state = randint(1, 2**256)
        
    def next(self):
        sP = self.state*self.P
        r = Integer(sP[0])
        self.state = Integer((r*self.P)[0])
        rQ = r*self.Q
        return Integer(rQ[0])>>8
```

and outputs:

```python
r1 = 135654478787724889653092564298229854384328195777613605080225945400441433200
r2 = 16908147529568697799168358355733986815530684189117573092268395732595358248
ct = c2c59febe8339aa2eee1c6eddb73ba0824bfe16d410ba6a2428f2f6a38123701
```

## Task analysis

The task name and description is hinting at https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number or more importantly at infamous https://en.wikipedia.org/wiki/Dual_EC_DRBG

The idea is that points P and Q are given arbitrarly and perhaps they are not as random as they may seem.
If there is a relation `d*Q = P` then one could recover the state of the RNG using just a single output.

## Solution

### Recover relation between P and Q

Task suggests that number are small so we just bruteforce:

```sage
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
curve = EllipticCurve(GF(p), [-3,b])
P = curve.lift_x(110498562485703529190272711232043142138878635567672718436939544261168672750412)
Q = curve.lift_x(67399507399944999831532913043433949950487143475898523797536613673733894036166)
for i in range(2,200):
    if Q*i == P:
        d = i
        break
print(d)
```

And we get back `173.`

### Recover RNG state

Now let's analyse how exactly we can recover the RNG state.
What we get back from the RNG is `return Integer(rQ[0])>>8`.
We can skip for a moment this `>>8`, since we can just bruteforce those lower 8 bits and test all possible options.
So we know `x-coordinate` of point `r*Q`.
We also know that RNG state is set to `self.state = Integer((r*self.P)[0])` so to `x-coordinate` of `r*P`.

From the relation we got, we know that `r*Q*173 = r*P`.

This means that knowing point `r*Q` we automatically know also point `r*P`, and it's `x-coordinate` is RNG state we need.

1. We fill `r1` with 8 zero bits at the end
2. We check every possible setting of those last 8 bits
3. We use the above relation to recover potential RNG state
4. We check if such state would give us the second RNG value we know
5. If so, then we generate next value which is AES key.

```sage
    r2 = 16908147529568697799168358355733986815530684189117573092268395732595358248
    r1 = 135654478787724889653092564298229854384328195777613605080225945400441433200 << 8
    for i in range(512):
        potential_x = r1+i
        try:
            point = d * curve.lift_x(potential_x)
            recovered_state = Integer(point[0])
            rng = RNG()
            rng.state=recovered_state
            if rng.next() == r2:
                print('key',rng.next())
                break
        except:
            pass
```

From this we get `('key', 380402561809199154387574835674243674541619792838103369955275792247709427466)`

### Decrypt flag

```python
def main():
    r = '380402561809199154387574835674243674541619792838103369955275792247709427466'
    aes_key = SHA256.new(r.encode('ascii')).digest()
    cipher = AES.new(aes_key, AES.MODE_ECB)
    print(cipher.decrypt("c2c59febe8339aa2eee1c6eddb73ba0824bfe16d410ba6a2428f2f6a38123701".decode("hex")))


main()
```

And we get `utflag{numbers_up_my_sl33v3_l0l}`
