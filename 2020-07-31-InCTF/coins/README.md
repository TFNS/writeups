# Coins (misc/ppc, 100p, 96 solved)

## Description

In the task we can connect to a simple service which asks us to solve a version of `coin balance puzzle`.

There are `N` coins with identical (unknown) weight, and one additional coin with different weight.
We can ask the service about XOR of weights of coins in range `[a,b]` (inclusive).
The goal is to decide which coin has different weight.

## Solution

The solution here is pretty simple and involves binary search.
We can simply ask about first half of the range and if the XOR is not `0` then the weird coin has to be in this half, and if XOR is `0` then coin has to be in the other half.
Note here: we need to ask about even-size range!
Otherwise we would have eg. `5^5^5 = 5`.

This special consideration makes it tricky because we arrive at 2 coins at the end.
The solution is to make two additional sets, one including one of those coins and another the other, and also consider the case when we have for example `[0,1]` or `[N,N+1]` and there is no way to construct both sets.

```python
def binsearch(oracle, sl, sh):
    search_low = sl
    search_high = sh
    while True:
        if search_high - search_low == 1:
            if search_low != 0:
                if oracle(search_low - 1, search_low):
                    return search_low
            if search_high != sh:
                if oracle(search_high, search_high + 1):
                    return search_high
            if search_low == 0:
                return 0
            elif search_high == sh:
                return search_high
        search_mid = (search_low + search_high) // 2
        if (search_mid - search_low) % 2 != 1:
            search_mid += 1
        if oracle(search_low, search_mid):
            search_high = search_mid
        else:
            search_low = search_mid
```

We can easily test this with a sanity check:

```python
def local_oracle(a, b, w):
    from operator import xor
    result = reduce(xor, w[a:b + 1], 0) != 0
    return result


def sanity():
    for i in range(10000):
        import random
        weights = [5 for _ in range(random.randint(100, 2000))]
        index = random.randint(0, len(weights))
        weights.insert(index, 10)
        res = binsearch(lambda a, b: local_oracle(a, b, weights), 0, len(weights) - 1)
        assert index == res
```

Now that it works we can plug this in to the real oracle:

```python

def PoW(suffix, digest):
    for prefix in itertools.product(string.ascii_letters + string.digits, repeat=4):
        p = "".join(prefix)
        if hashlib.sha256(p + suffix).hexdigest() == digest:
            return p


def oracle(s, a, b):
    send(s, str(a) + " " + str(b))
    response = receive_until(s, "\n")
    x = re.findall("\d+", response)[0]
    return x != '0'


def solve(s, coins):
    res = binsearch(lambda a, b: oracle(s, a, b), 0, coins - 1)
    print(res)
    return res


def main():
    host = "34.74.30.191"
    port = 1337
    s = nc(host, port)
    task = receive_until(s, ":")
    task = re.findall("XXXX\+(.*)\) == (.*)", task)[0]
    print(task)
    p = PoW(task[0], task[1])
    print(p)
    send(s, p)
    x = receive_until(s, "\n")
    x = receive_until(s, "\n")
    x = receive_until(s, "\n")
    while True:
        try:
            coins = receive_until(s, "\n")
            print(coins)
            coins = int(re.findall("\d+", coins)[0])
            print('coins', coins)
            x = receive_until(s, "\n")
            solution = solve(s, coins)
            print('solution', solution)
            send(s, "! " + str(solution))
            x = receive_until(s, "\n")
            print(x)
        except:
            interactive(s)
```

And we get: `inctf{1f_y0u_c4n_dr3am_y0u_c4n_s34rch_1n_logn}`
