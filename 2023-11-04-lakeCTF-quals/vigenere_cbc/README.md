# Vigenere-CBC (crypto)

## Introduction

In the task we get access to [source code](vigenere.py).
The code implements Vigenere cipher, however it adds a cipher-block-chaining mechanism on top, seemingly to avoid ECB-like artifacts with the same plaintext fragments getting encrypted into the same ciphertext.

## Analysis

The issue is obviously that Vigenere is a stream cipher, not a block cipher, so this whole idea doesn't make much sense at all.
If we can guess first character of the `key`, then first character of every block will be decrypted correctly - this is because first character of 1st block gets decrypted using known IV and then first character of 2nd block is mixed with properly decrypted first character of 1st block, and so on.

## Solution

We could approach this just like any other Vigenere encryption - guess k-th element of the key and check statistics on every k-th decrypted plaintext character of each block.
But we don't really have much data to work with, so statistical analysis might be rough.
It's much easier to try to find a `crib` instead:

- Bruteforce first 4 elements of the key (we know charset is only 26 characters, so it's not that much)
- Check first 4 decrypted bytes of every block and look for common short english cribs like "ARE", "THE", "AND", "HAD", "HAVE", "WAS", "WERE", "THIS", "THAT" etc.
- For each key candidate where a crib was found check if other decrypted plaintext pieces look sensible.

```python
def brute():
    CTXT = 'AFCNUUOCGIFIDTRSBHAXVHZDRIEZMKTRPSSXIBXCFVVNGRSCZJLZFXBEMYSLUTKWGVVGBJJQDUOXPWOFWUDHYJSMUYMCXLXIWEBGYAGSTYMLPCJEOBPBOYKLRDOJMHQACLHPAENFBLPABTHFPXSQVAFADEZRXYOXQTKUFKMSHTIEWYAVGWWKKQHHBKTMRRAGCDNJOUGBYPOYQQNGLQCITTFCDCDOTDKAXFDBVTLOTXRKFDNAJCRLFJMLQZJSVWQBFPGRAEKAQFUYGXFJAWFHICQODDTLGSOASIWSCPUUHNLAXMNHZOVUJTEIEEJHWPNTZZKXYSMNZOYOVIMUUNXJFHHOVGPDURSONLLUDFAGYGWZNKYXAGUEEEGNMNKTVFYZDIQZPJKXGYUQWFPWYEYFWZKUYUTXSECJWQSTDDVVLIYXEYCZHYEXFOBVQWNHUFHHZBAKHOHQJAKXACNODTQJTGC'
    prefix = 4
    for a in string.ascii_uppercase:
        for b in string.ascii_uppercase:
            for c in string.ascii_uppercase:
                for d in string.ascii_uppercase:
                    KEY = (a + b + c + d).ljust(BLOCKLENGTH, 'A')
                    decrypted = vigenere_cbc_dec(CTXT, KEY)
                    vals = [c[:prefix] for c in chunk_with_remainder(decrypted, BLOCKLENGTH)]
                    for v in vals:
                        if 'THIS' in v:
                            print(KEY, vals)
```

We get some candidates and best looking one is:

```
CVPYAAAAAAAAAAAAAAAA ['THIS', 'ITHM', 'NDAL', 'AGEN', 'ALON', 'RITT', 'IVEY', 'NFOR', 'SCIP', 'MEST', 'TTHE', 'OESN', 'PHER', 'BEUN', 'SOFY', 'ASIS', 'ENIT', 'REAN', 'VENC', 'BELI', 'DEIS', 'LYDO', 'ILLJ']
```

Once we hit some sensible looking crib we can start a classic `crib dragging` approach - find a word prefix for which we know most likely suffix, expand the candidate key with bytes necessary to decrypt that suffix and verify if for all other blocks we got something correct.

```python
def crib():
    CTXT = 'AFCNUUOCGIFIDTRSBHAXVHZDRIEZMKTRPSSXIBXCFVVNGRSCZJLZFXBEMYSLUTKWGVVGBJJQDUOXPWOFWUDHYJSMUYMCXLXIWEBGYAGSTYMLPCJEOBPBOYKLRDOJMHQACLHPAENFBLPABTHFPXSQVAFADEZRXYOXQTKUFKMSHTIEWYAVGWWKKQHHBKTMRRAGCDNJOUGBYPOYQQNGLQCITTFCDCDOTDKAXFDBVTLOTXRKFDNAJCRLFJMLQZJSVWQBFPGRAEKAQFUYGXFJAWFHICQODDTLGSOASIWSCPUUHNLAXMNHZOVUJTEIEEJHWPNTZZKXYSMNZOYOVIMUUNXJFHHOVGPDURSONLLUDFAGYGWZNKYXAGUEEEGNMNKTVFYZDIQZPJKXGYUQWFPWYEYFWZKUYUTXSECJWQSTDDVVLIYXEYCZHYEXFOBVQWNHUFHHZBAKHOHQJAKXACNODTQJTGC'
    known = "CVPY"
    KEY = known.ljust(BLOCKLENGTH, "A")
    s = len(known)
    for c in chunk_with_remainder(vigenere_cbc_dec(CTXT, KEY), BLOCKLENGTH):
        print(c[:s], c[s:])


crib()
```

We can for example try to guess that `BELI` is prefix for `BELIEVE` or that `CIP` in `SCIP` is prefix for `CIPHER`.
We expand the key and check if rest of the blocks still make sense.
Eventually we get the full key: `CVPYPWQCCLQYYMVAWURJ` which gives us:

```
THISISAVERYLONGFLAGW 
ITHMANYBLOCKSTOHIDEA 
NDALLINCAPITALSTHEFL 
AGENDSHERENOWFOLLOWS 
ALONGTEXTTHETEXTWASW 
RITTENONLYINORDERTOG 
IVEYOUMOREINFORMATIO 
NFORBREAKINGVIGENERE 
SCIPHERSINCEITSOMETI 
MESTAKESSOMETEXTTOGE 
TTHESTATISTICSRIGHTD 
OESNTITITVIGENERESCI 
PHERWASLONGTHOUGHTTO 
BEUNBREAKABLEHUNDRED 
SOFYEARSPASSEDUNTILK 
ASISKIBROKEITSINCETH 
ENITISNOTSECUREANYMO 
REANDITSEEMSTHATNOTE 
VENCBCCANSAVEITDOYOU 
BELIEVETHATCOUNTERMO 
DEISANYBETTERIHONEST 
LYDOUBTITSINCEITISST 
ILLJUSTASUM
```

so we submit `EPFL{THISISAVERYLONGFLAGWITHMANYBLOCKSTOHIDEANDALLINCAPITALSTHEFLAGENDSHERE}`

