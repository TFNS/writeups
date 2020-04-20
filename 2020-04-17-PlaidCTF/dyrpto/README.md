# dyrpto (crypto, 250p, 66 solved)

In the task we get some [protobuf generated code](message_pb2.py), [protobuf definition](message.proto), [actual task code](generate_problem.py) and [outputs](output.txt).

## Task analysis

The task is pretty straightforward:

1. Strong random 4096 bits RSA key is generated with public exponent 3
2. Flag is stored in protobuf object with id=0 and serialized to string
3. Payload is then padded with 24 urandom bytes
4. Finally it gets encrypted via RSA
5. Flag is again stored in protobuf object, now with id=1 and serialized to string
6. Payload is then padded with new set of 24 urandom bytes
7. Finally it gets encrypted via RSA

We know the public key, len of the serialized payload and the outputs.

## Vulnerability - Coppersmith's short pad + Franklin-Reiter related-message

Issue with this setup is that we have low public exponent and at the same time the length of padding is insufficient.
Coppersmith showed that in such case, it's possible to recover the original message -> https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Coppersmith%E2%80%99s_short-pad_attack

Once we recover padding, we can apply Franklin-Reiter related-message attack to recover the message, see: https://github.com/p4-team/ctf/tree/master/2018-03-10-n1ctf/crypto_rsapadding

## Small twist

There is a little twist in the task, because the messages are not actually identical!
If we use the provided protobuf code and dump example messages with id=0 and id=1 we will see that they start differently:

```
\x08\x01\x12\x8a\x02pctf{abcdab...
\x08\x00\x12\x8a\x02pctf{abcdab...
```

Fortunately this id is not random, but constant, so we can include this in the solver, and subtract at opportune time.

## Solution

We borrow some of the code from hellman http://mslc.ctf.su/wp/confidence-ctf-2015-rsa1-crypto-400/ and we get:

```python
def coppersmith_short_pad(n, e, c1, c2, v):
    PRxy.<x,y> = PolynomialRing(Zmod(n))
    PRx.<xn> = PolynomialRing(Zmod(n))
    PRZZ.<xz,yz> = PolynomialRing(Zmod(n))
     
    g1 = x**e - c1
    g2 = (x + y + v)**e - c2
     
    q1 = g1.change_ring(PRZZ)
    q2 = g2.change_ring(PRZZ)
     
    h = q2.resultant(q1)
    h = h.univariate_polynomial()
    h = h.change_ring(PRx).subs(y=xn)
    h = h.monic()
     
    roots = h.small_roots(X=2**(24*8), beta=0.387) 
    diff = roots[0]
    return int(diff)
```

This method transposes the problem a bit, by assuming that `message` is actually `x=(msg+pad1)` and second message is therefore `x+y=msg+(pad2-pad1)`, hence the first polynomial is `g1 = x**e - C1` without any other components.
Notice we have this special component `v` which is nothing else but our large constant coming from protobuf.

By running this we can recover the `y` value, which is `(pad2-pad1)`

## Coppersmith parameters selection

One word of comment for `small_roots` parameters, since it tends to baffle some people, what those parameters actually mean and how to choose them.

We created polynomial `h` of degree `e` such that `h(pad2-pad1) = 0`, and we want to find value of this root `pad2-pad1`.

Coppersmith's method allows to find small roots of polynomials modulo some factor of `N`.
The factor has to be larger than `N^beta` (where `beta` is between `0` and `1`), however the smaller `beta` we choose, the smaller roots we can find!
Specifically we can find only roots up to `N^(beta^2)/d` where `d` is the degree of polynomial, so `e=3` for us.

In our case we know that we're looking for `24*8 = 192` bits root, polynomial has degree 3, and both factors of `N` are about `N^0.5` and `N` has 4096 bits.

We'd need `beta^2/3` to be at least `1/20` (because `4096/20 > 192`) to be certain we can find the root.
This implies `beta ~= sqrt(3/20) ~= 0.387`
And this is fine, because `0.387 < 0.5` so we're still in the safe zone.

Parameter `X` is to set the max root value we're interested in, and obviously since both `pad1` and `pad2` are at most `24*8=192` bits long, then `pad2-pad1` difference can't be more than that.

Now we can apply second stage:

```python
def gcd(a, b): 
    while b:
        a, b = b, a % b
    return a.monic()

def franklin(n, e, diff, c1, c2, v):
    R.<x> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x + diff + v)^e - c2
    return -gcd(g1, g2).coefficients()[0]
```

To recover the flag.
We combine this with:

```python
def main():
    n = 647353081512155557435109029192899887292162896024387438380717904550049084072650858042487538260409968902476642050863551118537014801984015026845895208603765204484721851898066687201063160748700966276614009722396362475860673283467894418696897868921145204864477937433189412833621006424924922775206256529053118483685827144126396074730453341509096269922609997933482099350967669641747655782027157871050452284368912421597547338355164717467365389718512816843810112610151402293076239928228117824655751702578849364973841428924562822833982858491919896776037660827425125378364372495534346479756462737760465746815636952287878733868933696188382829432359669960220276553567701006464705764781429964667541930625224157387181453452208309282139359638193440050826441444111527140592168826430470521828807532468836796445893725071942672574028431402658126414443737803009580768987541970193759730480278307362216692962285353295300391148856280961671861600486447754303730588822350406393620332040359962142016784588854071738540262784464951088700157947527856905149457353587048951604342248422901427823202477854550861884781719173510697653413351949112195965316483043418797396717013675120500373425502099598874281334096073572424550878063888692026422588022920084160323128550629
    e = 3
    c1 = 0x314193fd72359213463d75b4fc6db85de0a33b8098ba0ba98a215f246e7f6c4d17b59abb7e4ceb824d7310056d6574b13956f1b3d1ac868b72f6b98508b586566d71474da72c2ae4d3273c80757d0160f703ca0b14a0504509d92d4c09a733feae349a5b512fdcea46574a29b8507c60b5c49edd7641b19f98845688c38fc67a35432653140cbb5abc17d3c32f3720e4549797877ca9cae61aa75df936e41200906729a0dac3b7b18289681dbaf4a3bfdf9a3acf2efac8c5e5f873ede32ccbfcae438bd813601f4fe5290f2b999d988f3d0f423d76a6ae8a5dee2dd17aa7996e8f96fe9c76ac379f6dabb6def2dc05c8561fad1722706736aba8a20385d2054e1929682157f1d201b22a224aafb6004164f3325124279e16c99471a341b88300bd0161cdeca4b9d92bf761a0ed74c2b151a62d10c4b0cdbd3e8f657f76f3ac88430a4a89ab4a913d9a55dae150b6e42df6e161382055782c0ff05e635fb2e50e826f08440266dc60ca081b1d17c18145c6d45a1fa0bb439428e4796346bc912e897897dc47097d0047b28e0ff1e52ea27726ce444b1287b250ed5a43a2e84c37cba4c2e39b5c389d671c0ea0639d3a2c6092cc1ee50e35c810eb5d053190d7594c52995ac95b7889a61d2afe7d6dc33b0e13ab4eddd791f01a11b336549154bb894b5afc0dcc5b5b4ce9f162f423b7dd80ce70a73ddbda0333c12eeea408e97c
    c2 = 0x0b9bbdf92c4c5099708b911813737e3f17ef3d554bceb65d2681b377a2c5bdb8f1c634602bda2ec9b2b7b6f894f1592c944865594740e9fd139d07db9d309a93d2a33ec3a0455acf083bc02fd8e1f685804ecefe7d55462847c93badf44464f55a0fa6a8fc8aae839630efc00aaee30c9ad2a5b8f4410141bb17b29f312e2e1c2c963324776e7ea7ca90d717661a86d7da8f4cb6a72be1b8f979974032667733d3db07f528cb086f81edafe0a8ec28d890455fc8f382a79193e3d04284b9d0b13d181159191e8cd6401a592c464538a0145a88f8f2e5522ccc4aa3cf2779c2efe4d0dcb501f75011e063a4713eb3067a85761d79ed359db4a038fe2369f3b0d7aab29fd65aeabc3c408bbbfe9a03954d8a9af955d61e853b15183137bfb2654fc41aa9aaad6d4c68a6a034373e9600805ed0ab7a77c0ac9199d549c26c8bfa43ea449d45fe924fe728a98bc3f6575d8710012065ce72fc0fdea4e81b438fbd31afc4733bb15bc4d11cf103e89923bf04ff336c53c536a9456e8751233f8be29166e4a7982689988983bd351f875feea46a7a9875005f76e2e24213a7e6cc3456c22a9813e2b75cba3b1a282d6ab207e4eddba46992104a2ae4ccb2f5b6f728f42ae2f0a06e91c8772971e4169a5ee891d12465f673c3264b5619d5e05d97ee4d8da63fe9e9633af684fdf5193e47bf303621c2f5be35ef1e20f282c4d83bf03e
    v = 0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    diff = coppersmith_short_pad(n, e, c1, c2, v)
    flag = franklin(n, e, diff, c1, c2, v)
    print(long_to_bytes(flag))

main()
```

And get back:

```
I never know what to put into these messages for CTF crypto problems. You gotta pad the length but flags can only reasonably be so long. Anyway, the flag should be coming any moment now... Ah, here it comes! The flag is: PCTF{w0w_such_p4d_v3ry_r34l1st1c_d0g3_crypt0}
```

