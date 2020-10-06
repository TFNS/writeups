# Petition (crypto/zajebiste, 493p, 5 solved)

## Description

In the task we get [source code](Challenge.java) and access to remote server.
We also get a Dockerfile which simply brags that this is supposed to work on `openjdk:latest`.
It's basically a 0day hunt.

## Code analysis

The code is pretty short and simple.
We are supposed to provide a `SHA1-DSA` signature for some provided message.
The twist is that this signature is supposed to be valid for 100 randomly generated public keys.

```java
var petition = Base64.getDecoder().decode(new Scanner(System.in).next());
var message = "We want to see the flag!".getBytes();

for (int i = 0; i < 100; i++) {

    // Create a new key
    BigInteger x;
    do {
        x = new BigInteger(q.bitLength(), new Random());
    } while (q.compareTo(x) <= 0);
    var y = g.modPow(x, p);
    var publicKeySpec = new DSAPublicKeySpec(y, p, q, g);
    var keyFactory = KeyFactory.getInstance("DSA");
    var publicKey = keyFactory.generatePublic(publicKeySpec);

    // Verify signature
    var signature = Signature.getInstance("SHA1withDSA");
    signature.initVerify(publicKey);
    signature.update(message);
    if (!signature.verify(petition)) {
        System.out.println("This petition looks fraudulent!");
        return;
    }
}

System.out.println("OK, this has been signed by at least 100 people!");
System.out.println(new Scanner(new File("flag.txt")).nextLine());
```

Essentially, this means there is a vulnerability, which allows to forge a signature valid for any key, absolutely breaking DSA.
Math behind DSA is not very complex, and it's unlikely there is an attack on that.
This leaves us with JDK code.

## 0day in JDK Digital Signature Algorithm

The buggy code is:

```java
// some implementations do not correctly encode values in the ASN.1
// 2's complement format. force r and s to be positive in order to
// to validate those signatures
if (r.signum() < 0) {
    r = new BigInteger(1, r.toByteArray());
}
if (s.signum() < 0) {
    s = new BigInteger(1, s.toByteArray());
}

if ((r.compareTo(presetQ) == -1) && (s.compareTo(presetQ) == -1)) {
    BigInteger w = generateW(presetP, presetQ, presetG, s);
    BigInteger v = generateV(presetY, presetP, presetQ, presetG, w, r);
    return v.equals(r);
} else {
    throw new SignatureException("invalid signature: out of range values");
}
```

If we compare this with DSA verification algorithm at https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Verifying_a_signature we can see that already first point is not fulfilled here!

Notice that the code checks for negative `r` and `s` and turns them into signed values, and then verifies that `r` and `s` are `<q`, but the algorithm clearly states to verify that `0<r<q`.
There is no check if `r=0` or `s=0`!

## Attack

Let's look at what happens if `r=0`:

```
w = modinv(s,q)
u1 = hash(msg)*w mod q
u2 = r*w mod q = 0
v = (g^u1 * y^u2 mod p) mod q = (g^u1 mod p) mod q
```

To have a valid signature we need `r==v` and therefore we want:

```
(g^u1 mod p) mod q == 0
```

which means that `g^u1 mod p` must be a multiple of `q`.

We know that `p-1 = 2*q`, so there are not that many options here really, we can get either `q`, or `2*q`.

So we want to solve a discret logarithm for `g^u1 mod p == q` or `g^u1 mod p == 2*q`.
In general case DLP is hard, but here it's actually possible to solve.
Using some `magic` we arrive at `u1 = (q-1)/2` and we can verify that `pow(g,u1,p) % q == 0`.

Now we just need to compute `s` component of the signature.
We know `u1 = hash(msg) * modinv(s,q) mod q` hence:

```
u1 = hash(msg) * modinv(s,q) mod q
u1 * modinv(hash(msg),q) = modinv(s,q)
modinv(u1 * modinv(hash(msg),q),q) = s mod q
s = modinv(u1 * modinv(hash(msg),q),q)
s = modinv((q-1)/2 * modinv(hash(msg),q),q)
```

Therefore we do:

```python
q = 0xb9957d3a9e037ec8b1a2d292f6f44dd4ebc50545
msg = 'We want to see the flag!'
s = modinv((q - 1) / 2 * modinv(bytes_to_long(hashlib.sha1(msg).digest()), q), q)
```

And we get `s = 966615538281806264377774098324087863394508630725`

Now we can construct the payload to get the flag:

```java
DerOutputStream derOutputStream = new DerOutputStream();
DerValue[] seq = new DerValue[2];
seq[0] = new DerValue(DerValue.tag_Integer,new BigInteger("0").toByteArray());
seq[1] = new DerValue(DerValue.tag_Integer, new BigInteger("966615538281806264377774098324087863394508630725").toByteArray());
derOutputStream.putSequence(seq);
var sig = derOutputStream.toByteArray();
System.out.println(new String(Base64.getEncoder().encode(sig)));
```

This gives us `MBoCAQACFQCpUIoxqxO4ABpDb0jdjjEuNEJqxQ==`

We can use the provided code to verify this locally, and we can also send this to remote to grab the flag: `tstlss{3_billion_devices_cannot_be_wrong}`
