# Nibiru (crypto, 955, 10 solved)

In the challenge we get a [pdf](Nibiru.pdf) with some ciphertext and description of a cryptosystem.

## Implement encrypt/decrypt

First step to understand the task, was to actually implement the algorithm:

```python
def decrypt(ct, key, offset):
    left = [c for c in string.uppercase if c not in key]
    alphabet = key + "".join(left)
    result = ''
    for c in ct:
        if c not in alphabet:
            result += c
        else:
            new_index = alphabet.index(c)
            current_index = (new_index - offset) % len(alphabet)
            current = alphabet[current_index]
            result += current
            offset = alphabet.index(current) + 1
    return result


def encrypt(pt, key, offset):
    left = [c for c in string.uppercase if c not in key]
    alphabet = key + "".join(left)
    result = ""
    for c in pt:
        if c not in alphabet:
            result += c
        else:
            current_index = alphabet.index(c)
            new_index = (current_index + offset) % len(alphabet)
            new = alphabet[new_index]
            result += new
            offset = current_index + 1
    return result
```

## Stage 1

Now that we can encrypt and decrypt data, we need to somehow break the ciphertext we got.
In order to do that, it's much simpler to assume a different model for the encryption.
Let's assume we have a map `int -> int` where `0 -> 5` means that letter `A` is 5th letter of the keyed alphabet, and `3 -> 7` means that letter `D` is 7th letter of the keyed alphabet.

With such model, encryption becomes:

```python
for c in pt:
    current_index = alphabet[c]
    new_index = (current_index + offset) % len(alphabet)
    new = alphabet.index(new_index)
    result += string.uppercase[new]
    offset = current_index + 1
return result
```

Even more, if we omit the first, unknown, offset:

```python
for i in range(1,len(pt)): 
    new_index = (alphabet[pt[i]] + alphabet[pt[i-1]]) % len(alphabet)
    new = alphabet.index(new_index)
    result += string.uppercase[new]
return result
```

Notice that this basically means that:

```python
for i in range(1,len(pt)): 
    assert alphabet[ct[i]] == (alphabet[pt[i]] + alphabet[pt[i-1]]) % len(alphabet)
return result
```

Has to hold.

Now our goal is to recover the permutation in the original `alphabet`, which turns the plaintext we know into the ciphertext.
We decided to simply pass this to Z3:

```python
    import z3
    solver = z3.Solver()
    alphabet_order = [z3.Int("alphabet_%d" % i) for i in range(len(string.uppercase))]
    for a in alphabet_order:
        solver.add(a >= 0)
        solver.add(a < len(string.uppercase))
    alphabet_len = len(alphabet_order)
    for i in range(alphabet_len):
        for j in range(alphabet_len):
            if i != j:
                solver.add(alphabet_order[i] != alphabet_order[j])
    pt = map(lambda x: ord(x) - ord('A'), pt.upper())
    ct = map(lambda x: ord(x) - ord('A'), ct.upper())
    for i in range(1, len(pt) - 1):
        solver.add((alphabet_order[pt[i + 1]] + alphabet_order[pt[i]] + 1) % alphabet_len == alphabet_order[ct[i + 1]])
    print(solver.check())
    model = solver.model()
    alphabet = [None] * alphabet_len
    for i in range(alphabet_len):
        idx = model[alphabet_order[i]].as_long()
        alphabet[idx] = string.uppercase[i]
    alphabet = "".join(alphabet)
    print(alphabet)
```

This was taking a while, so we decided to help Z3 a bit, by assuming that maybe the key is short, and doesn't contain weird letters like `VWXYZ`, and we added constraint:

```python
for i in range(21, alphabet_len):
    solver.add(alphabet_order[i] == i)
```

Which immediately gave us: `FEARBCDGHIJKLMNOPQSTUVWXYZ`

We could confirm this was in fact a proper key, since encrypting plaintext using this key gives the ciphertext, with the exceptoion for first character, since it requires proper offset.
This we could just brute-force to find the right value `10`.

Now we could recover entire message:

```
I FEAR MY ACTIONS MAY HAVE DOOMED US ALL. 
AFTER MONTHS OF FILLING OUR HOLD WITH TREASURE, WE WERE ABOUT TO SET SAIL WHEN WORD WAS DELIVERED OF AN EVEN GREATER PRIZE: A SARCOPHAGUS OF THE PUREST CRYSTAL, FILLED TO THE BRIM WITH BLACK PEARLS OF IMMENSE VALUE. 
A KING'S RANSOM! THE MEN AND I WERE OVERTAKEN WITH A DESIRE TO FIND THIS GREAT TREASURE. 
AND AFTER SEVERAL MONTHS OF SEARCHING, FIND IT WE DID. 
WHAT WE DIDN'T REALIZE WAS THAT THE ENTITY THAT DWELLED INSIDE THAT CRYSTAL SARCOPHAGUS HAD BEEN SEARCHING FOR US AS WELL. 
IN OUR THIRST FOR POWER AND WEALTH, WE HAD DISCOVERED A TERRIBLE EVIL. IT PREYED UPON OUR FEARS, DRIVING US TO COMMIT HORRIBLE ACTS. 
FINALLY, IN AN ACT OF DESPERATION TO STOP WHAT WE HAD BECOME, I SET THE SHIP ASHORE ON THE MISSION COAST, IN A COVE WE NAMED AFTER WHAT WE WOULD SOON BRING THERE: CRYSTAL COVE.
WE BURIED THE EVIL TREASURE DEEP, DEEP UNDERGROUND. 
I CONCEALED ITS LOCATION ABOARD THE SHIP AND ARTFULLY PROTECTED IT BY AN UNCRACKABLE CIPHER. 
I BROUGHT THE SHIP HERE, TO THE TOP OF THIS MOUNTAIN, TO STAY HIDDEN FOREVER. I ENCODED THE FLAG WITH THE VIGENERE CIPHER, FTGUXI ICPH OLXSVGHWSE SOVONL BW DOJOFF DHUDCYTPWMQ. 
ONE OF THE TWELVE EQUIVALENT KEYS USED TO DECODE THIS MESSAGE WAS USED.
```

## Stage 2

Now we have Vigenere ciphertext `FTGUXI ICPH OLXSVGHWSE SOVONL BW DOJOFF DHUDCYTPWMQ`, which supposedly is encrypted with one of other keys which can decrypt the initial ciphertext.

The goal is to recover all those other keys, but now we have much more plaintext to work with.

The idea we use is pretty much identical, but this time we use a direct approach, instead of Z3.
We know that the property:

```python
assert alphabet[ct[i]] == (alphabet[pt[i]] + alphabet[pt[i - 1]] + 1) % len(alphabet)
```

has to hold for the whole plaintext/ciphertext.

We can try to guess few initial alphabet entries, use them to propagate some more (eg. if we know `alphabet[pt[i]]` and `alphabet[pt[i-1]]` we can immediately deduce the value of `alphabet[ct[i]]`), and check for any inconsistency.
If something doesn't match, it means we guessed the alphabet entries wrong.
Last letter of plaintext/ciphertext might have propagated some new value, useful at the beginning of the text, so we have to pass multiple times, so make sure we propagated everything.
Then we can check if we managed to recover whole alphabet, and if so, then print it:

```python
def convert_alphabet(alphabet_order):
    result = ['?'] * 26
    for i, c in enumerate(alphabet_order):
        if c is not None:
            result[c] = string.uppercase[i]
    return result

def guess_key(pt, ct):
    alphabet_initial = [None for _ in string.uppercase]
    pt = map(lambda x: ord(x) - ord('A'), pt)
    ct = map(lambda x: ord(x) - ord('A'), ct)
    for first in range(26):
        for second in range(26):
            for third in range(26):
                alphabet = alphabet_initial[:]
                alphabet[pt[0]] = first
                alphabet[pt[1]] = second
                alphabet[pt[2]] = third
                try:
                    for step in range(100):
                        for i in range(1, len(pt)):
                            if alphabet[pt[i]] is not None and alphabet[pt[i - 1]] is not None:
                                offset = alphabet[pt[i - 1]] + 1
                                if alphabet[ct[i]] is not None:
                                    assert alphabet[ct[i]] == (alphabet[pt[i]] + alphabet[pt[i - 1]] + 1) % len(alphabet)
                                else:
                                    alphabet[ct[i]] = (alphabet[pt[i]] + offset) % len(alphabet)
                    if '?' not in convert_alphabet(alphabet):
                        print("".join(convert_alphabet(alphabet)))
                except:
                    pass
```

This gives us:

```
BINTYRHMSXAGLQWEDKPVFCJOUZ
HQFISEJTAKURLVBMWCNXDOYGPZ
SKBXPIAVNGFTLCYQJRWOHEUMDZ
JVDQAMYIUCPELXHTBOFKWGSRNZ
FEARBCDGHIJKLMNOPQSTUVWXYZ
ACHKNQUXFRDILOSVYEBGJMPTWZ
WTPMJGBEYVSOLIDRFXUQNKHCAZ
YXWVUTSQPONMLKJIHGDCBRAEFZ
NRSGWKFOBTHXLEPCUIYMAQDVJZ
DMUEHOWRJQYCLTFGNVAIPXBKSZ
PGYODXNCWMBVLRUKATJESIFQHZ
UOJCFVPKDEWQLGAXSMHRYTNIBZ
```

All 12 equivalent keys!
Now we just test all of them to decrypt the Vigenere ciphertext and we get `IJCTF{SCOOBY DOOO HOMOGENOUS SYSTEM OF LINEAR CONGRUENCES}`
