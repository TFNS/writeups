# DLPoly (crypto, 676p, 28 solved)

## Description

In the task we get some [sage results](out.txt)
We have here a `Polynomial Ring` over `GF(p)` and a discrete logarithm problem to solve.

The data provided are not very accurate:

- They seemingly provide `G^x` while in reality it's `G^x % n`
- Task claims the unknown part of the flag is 7 bytes while in reality it's only 6

Anyway, we know polynomial `n` and `ct = G^flag % n` and our task is to recover the flag.

## Solution

### Reduce the problem a bit

From solving RSA Poly we know that `phi(n)` for polynomials in `PolynomialRing(GF(p))` is `(p^f1.degree()-1) * (p^f2.degree()-1) * ....(p^fk.degree()-1)` where `n = f1*f2*...*fk`, so `f` are factors of `n`.

We start off by noticing that:

```
ct = g^flag mod n
ct = g^(k*phi(n) + flag%phi(n)) mod n [for some integer k]
// using Euler totient theorem
ct = g^(flag%phi(n)) mod n
// using this phi(n) for polynomials
ct = g^(flag%(p^f1.degree()-1)) mod f1
```

lowest degree of `n` factor is `6` and `p^6-1 > flag` so we effectively just need to solve this logarithm:

```python
ct = g^flag mod f1
```

In reality we initially thought we will need this step to implement Pohlig-Hellman algorithm, so calculate DLP over all factors of `n` and combine via `CRT`, but it turned out the value was so small, it was not needed at all.

### Solve DLP over polynomial ring

While we just reduced polynomials to smaller, we still actually need to solve DLP.
Notive that we're missing only 6 bytes (even for 7, as task originally suggested, it's still doable).

We will use Baby-Step-Giant-Step for this, because it's the only DLP algorithm we can quickly implement:

```python
def baby_step_giant_step(step, modulo, ct, pt):
    known_small_powers = {0: 1}
    prev = 1
    for i in range(1, step):
        curr = (prev * pt) % modulo
        known_small_powers[curr] = i
        prev = curr
    print("Precomputed smalls")
    subtractor = inverse_mod(pt ^ step % modulo, modulo)
    x = ct
    i = 0
    while x not in known_small_powers:
        i += 1
        x = (x * subtractor) % modulo
    return step * i + known_small_powers[x]
```

We can verify this with simple sanity check on small numbers:

```python
p = 35201
P.<x>=PolynomialRing(GF(p))
n = P(1629*x^256 + 25086*x^255 + 32366*x^254 + 21665*x^253 + 24571*x^252 + 20588*x^251 + 17474*x^250 + 30654*x^249 + 31322*x^248 + 23385*x^247 + 14049*x^246 + 27853*x^245 + 18189*x^244 + 33130*x^243 + 29218*x^242 + 3412*x^241 + 28875*x^240 + 1550*x^239 + 15231*x^238 + 32794*x^237 + 8541*x^236 + 23025*x^235 + 21145*x^234 + 11858*x^233 + 34388*x^232 + 21092*x^231 + 22355*x^230 + 1768*x^229 + 5868*x^228 + 1502*x^227 + 30644*x^226 + 24646*x^225 + 32356*x^224 + 27350*x^223 + 34810*x^222 + 27676*x^221 + 24351*x^220 + 9218*x^219 + 27072*x^218 + 21176*x^217 + 2139*x^216 + 8244*x^215 + 1887*x^214 + 3854*x^213 + 24362*x^212 + 10981*x^211 + 14237*x^210 + 28663*x^209 + 32272*x^208 + 29911*x^207 + 13575*x^206 + 15955*x^205 + 5367*x^204 + 34844*x^203 + 15036*x^202 + 7662*x^201 + 16816*x^200 + 1051*x^199 + 16540*x^198 + 17738*x^197 + 10212*x^196 + 4180*x^195 + 33126*x^194 + 13014*x^193 + 16584*x^192 + 10139*x^191 + 27520*x^190 + 116*x^189 + 28199*x^188 + 31755*x^187 + 10917*x^186 + 28271*x^185 + 1152*x^184 + 6118*x^183 + 27171*x^182 + 14265*x^181 + 905*x^180 + 13776*x^179 + 854*x^178 + 5397*x^177 + 14898*x^176 + 1388*x^175 + 14058*x^174 + 6871*x^173 + 13508*x^172 + 3102*x^171 + 20438*x^170 + 29122*x^169 + 17072*x^168 + 23021*x^167 + 29879*x^166 + 28424*x^165 + 8616*x^164 + 21771*x^163 + 31878*x^162 + 33793*x^161 + 9238*x^160 + 23751*x^159 + 24157*x^158 + 17665*x^157 + 34015*x^156 + 9925*x^155 + 2981*x^154 + 24715*x^153 + 13223*x^152 + 1492*x^151 + 7548*x^150 + 13335*x^149 + 24773*x^148 + 15147*x^147 + 25234*x^146 + 24394*x^145 + 27742*x^144 + 29033*x^143 + 10247*x^142 + 22010*x^141 + 18634*x^140 + 27877*x^139 + 27754*x^138 + 13972*x^137 + 31376*x^136 + 17211*x^135 + 21233*x^134 + 5378*x^133 + 27022*x^132 + 5107*x^131 + 15833*x^130 + 27650*x^129 + 26776*x^128 + 7420*x^127 + 20235*x^126 + 2767*x^125 + 2708*x^124 + 31540*x^123 + 16736*x^122 + 30955*x^121 + 14959*x^120 + 13171*x^119 + 5450*x^118 + 20204*x^117 + 18833*x^116 + 33989*x^115 + 25970*x^114 + 767*x^113 + 16400*x^112 + 34931*x^111 + 7923*x^110 + 33965*x^109 + 12199*x^108 + 11788*x^107 + 19343*x^106 + 33039*x^105 + 13476*x^104 + 15822*x^103 + 20921*x^102 + 25100*x^101 + 9771*x^100 + 5272*x^99 + 34002*x^98 + 16026*x^97 + 23104*x^96 + 33331*x^95 + 11944*x^94 + 5428*x^93 + 11838*x^92 + 30854*x^91 + 18595*x^90 + 5226*x^89 + 23614*x^88 + 5611*x^87 + 34572*x^86 + 17035*x^85 + 16199*x^84 + 26755*x^83 + 10270*x^82 + 25206*x^81 + 30800*x^80 + 21714*x^79 + 2088*x^78 + 3785*x^77 + 9626*x^76 + 25706*x^75 + 24807*x^74 + 31605*x^73 + 5292*x^72 + 17836*x^71 + 32529*x^70 + 33088*x^69 + 16369*x^68 + 18195*x^67 + 22227*x^66 + 8839*x^65 + 27975*x^64 + 10464*x^63 + 29788*x^62 + 15770*x^61 + 31095*x^60 + 276*x^59 + 25968*x^58 + 14891*x^57 + 23490*x^56 + 34563*x^55 + 29778*x^54 + 26719*x^53 + 28613*x^52 + 1633*x^51 + 28335*x^50 + 18278*x^49 + 33901*x^48 + 13451*x^47 + 30759*x^46 + 19192*x^45 + 31002*x^44 + 11733*x^43 + 29274*x^42 + 11756*x^41 + 6880*x^40 + 11492*x^39 + 7151*x^38 + 28624*x^37 + 29566*x^36 + 33986*x^35 + 5726*x^34 + 5040*x^33 + 14730*x^32 + 7443*x^31 + 12168*x^30 + 24201*x^29 + 20390*x^28 + 15087*x^27 + 18193*x^26 + 19798*x^25 + 32514*x^24 + 25252*x^23 + 15090*x^22 + 2653*x^21 + 29310*x^20 + 4037*x^19 + 6440*x^18 + 16789*x^17 + 1891*x^16 + 20592*x^15 + 11890*x^14 + 25769*x^13 + 29259*x^12 + 23814*x^11 + 17565*x^10 + 16797*x^9 + 34151*x^8 + 20893*x^7 + 2807*x^6 + 209*x^5 + 3217*x^4 + 8801*x^3 + 21964*x^2 + 16286*x + 12050)

import random
factors = n.factor()
bits = 24
g = P.gen()
flag = random.randint(2**bits,2**(bits+1))
s = pow(g, flag, n)
f1 = factors[0][0]
a1 = s%f1
d1 = f1.degree()
assert s%f1 == pow(g, (flag % (p^d1-1)),f1)
flag_mod = baby_step_giant_step(isqrt(flag), f1, a1, g)
print(flag_mod)
assert flag_mod == flag % (p**d1-1)
```

The idea of the algorithm is rather simple, a classic meet-in-the-middle.
First you compute every possible `low bits` part of the logarithm, and then you do `big steps` by movign over the `high bits`, and check if combined you reach your target.

We could improve this a bit by excluding some values, since we know it should be printable ascii.
We also initially thought it's 7 bytes, and implemented a fancy version which split the range in half so 3.5 bytes for small and 3.5 bytes for large step...

Since we need 6 bytes, we can split in half, and thus `step = 2**24`.
This will require `2**24` memory and `2 * 2**24` computation, but it's still just few GB of RAM and few minutes to run.

We can now just plug in the original secret value and after few minutes we recover: `inctf{bingo!}`
