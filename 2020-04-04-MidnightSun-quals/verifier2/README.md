# Verifier2 (crypto, 201p, 22 solved)

A very guessy challenge, if it wasn't for the organizers failure and leaking some information with the flag for Verifier1.
The flag for Verifier1 said `midnight{number_used_once_or_twice_or_more}`, which clearly hints at `nonce` issue.

In this challenge we have a service which can sign stuff for us.
To get the flag we need to submit signature of some pre-defined string, however the application won't let us sign this particular string (the v1 acutally by mistake did allow this...).

By looking at the length of the signature we can see it's too short for DSA/RSA, because we get back 48 bytes only, so 384 bits.
This sounds like value on elliptic curve, more precisely a good match for `r,s` values fror 192 bits curve, most likely NIST P-192.

Another hint is that half of the signature we get back is identical for different inputs.
This is an artifact of using static/repated nonce in ECDSA:

1. Choose a random nonce `k` 
2. Calculate `P = k*G`
3. Set `r = P.x mod n`

It's clear that if `k` is repeated then there is a high chance to get identical `r` for different inputs, because point `G` is always the same for selected curve.

The `s` part of signature comes from:

```python
z = hash(data)
modinv(k, n) * (z + r * da) % n
```

This means that for two signatures we have:

```
s1 = modinv(k, n) * (z1 + r * da) % n
s2 = modinv(k, n) * (z2 + r * da) % n
```

Let's subtract those values and we get:

```
s1 - s2 = modinv(k,n)*((z1 + r * da) - (z2 + r * da)) % n
s1 - s2 = modinv(k,n)*((z1 - z2) + r * da - r * da) % n
s1 - s2 = modinv(k,n)*(z1 - z2) % n
k*(s1 - s2) = (z1 - z2) % n
k = (z1 - z2)*modinv(s1 - s2) % n
```

So we can calculate the value of the shared nonce `k`.

Now if we look back, we're missing only `da` part to calculate the `s` part of signature.
But let's look again at the equation to calculate `s`:

```
s = modinv(k, n) * (z + r * da) % n
```

We know everything apart from `da` here. We can do:

```
s = modinv(k, n) * (z + r * da) % n
s*k % n = (z + r * da) % n
(s*k % n -z) % n = r*da % n
(s*k % n -z) * modinv(r,n) %n = da
```

Now we can just plug values of `s1` or `s2` we have and recover `da`, and then calculate any signature we want:

```python
def forge_signature(c1, sig1, c2, sig2, input_data):
    hash_function = hashlib.sha1
    n = 6277101735386680763835789423176059013767194773182842284081  # NIST P-192
    s1 = bytes_to_long(sig1[24:])
    s2 = bytes_to_long(sig2[24:])
    r_bytes = sig1[:24]
    r = bytes_to_long(r_bytes)
    z1 = bytes_to_long(hash_function(c1).digest())
    z2 = bytes_to_long(hash_function(c2).digest())

    s_diff_inv = modinv(((s1 - s2) % n), n)
    k = (((z1 - z2) % n) * s_diff_inv) % n
    r_inv = modinv(r, n)
    da = (((((s1 * k) % n) - z1) % n) * r_inv) % n
    z = bytes_to_long(hash_function(input_data).digest())
    s = modinv(k, n) * (z + r * da) % n
    return (r_bytes + long_to_bytes(s)).encode("hex")
```

We use this with inputs grabbed from the service and get the flag: `midnight{number_used_once_or_twice_or_more_e8595d72819c03bf07e534a9adf71e8a}`
