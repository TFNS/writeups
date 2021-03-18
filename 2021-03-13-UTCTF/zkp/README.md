# Prove no knowledge (crypto, 946p, 75 solved)

## Description

```
I've been trying to authenticate to this service, but I'm lacking enough information.

nc crypto.utctf.live 4354
```

## Task analysis

Once we connect to the service we get:

```
Please authenticate with the service for 256 rounds
Prove knowledge of x such that g^x mod p = y
g: 2
p: 21715527412966631469552971169690128914062132118754918283497731012401819458899160644271200984004877991667698112111969859554672248832332341601818361659117300292394912107010536406527665819151052443699635469973012963906675594556841842816188836789562579097722593159433568704132198828039413395154960077442866739275639160772090039380941130568463418468068212798701517653648598178664137788181578590797421288972063084123880597980014584467405064300216976234905476393699113021738776957524460347175348677928965863838648282171908681617230540393901458294493124113826454719386324836823535815507071098688985018508655747533191750892299
y: 2241091281866981590713031672734151516300710020345565188317572943112262874486055910624883311174325855469406896929014346725513796451457514790588317088473326414916242575481653723476365986775055993759825427454400405547332712166357022867715325877245386300809314415721624475960206253796052312080526710876925035167963912222867096346872976548915196609439810593243985896390971845918939232140271548400629068566744052808262009630671957592752151744182924336729849909949901333769404020711741941239120933385667572185879280581475051872117705632349443652320091419374306501015530192437807190888120399553909591592141048509464548519061
Pick a random r. Send g^r mod p.
```

Each time we connect we get different `y`, so `x` is randomized.
Once we submit some value server asks:

```
Send r.
```

### Stage 1

First step is trivial, since we can choose any `r` we want and send `g^r mod p` to the server, because we know all parameters.
This is quite trivial, since we can just send `r = 0` and then `g^r mod p == 1`

### Stage 2

Once we pass this stage server asks:

```
Pick a random r. Send g^r mod p.
```

The same as before, but once we submit a value it asks:

```
Send (x + r) mod (p - 1).
```

We can't really expect to solve DLP here to recover `x`, so we need to figure out such value `r` that we can predict `(x+r) mod (p-1)`.

## Solution

We use here a simple trick that:

```python
pow(g, p - 1, p) * modinv(pow(g, x, p), p) == pow(g, (p - 1) - x, p)
```

We know all parameters, therefore we can easily calculate `pow(g, (p - 1) - x, p)` and therefore we know `g^r mod p` for `r = (p-1)-x`.

If we submit such `r`, then `x+r mod p-1 = x+(p-1)-x mod p-1 = p-1 mod p-1 = 0`

Now normally ZKP would randomize the challenge, so we would not know if we will be asked about `r` or `(x + r) mod (p - 1)` and we can't forge `r` for both of them, but here the challenges are deterministic and alternate.

This means we can do:

```python
import re

from crypto_commons.netcat.netcat_commons import nc, interactive, receive_until_match, receive_until, send
from crypto_commons.rsa.rsa_commons import modinv


def main():
    host = "crypto.utctf.live"
    port = 4354
    s = nc(host, port)
    print(receive_until_match(s, "p = y\n"))
    g = int(re.findall("\\d+", receive_until(s, "\n"))[0])
    p = int(re.findall("\\d+", receive_until(s, "\n"))[0])
    y = int(re.findall("\\d+", receive_until(s, "\n"))[0])
    print(g, p, y)
    grp = pow(g, p - 1, p) * modinv(y, p)
    for i in range(128):
        send(s, '1\n0\n' + str(grp) + "\n0")
    interactive(s)


main()
```

And get: `utflag{questions_not_random}`
