# Sizzling Bacon (beginner/crypto, 100p, 417 solved)

## Description

```
My buddy Francis is really into Bacon. He loves it so much that he gave me this encoded bacon-themed flag (he said he was inspired by the sound of sizzling bacon).

sSsSSsSSssSSsSsSsSssSSSSSSSssS{SSSsSsSSSsSsSSSsSSsSSssssssSSSSSSSsSSSSSSSSsSSsssSSssSsSSSsSSsSSSSssssSSsssSSsSSsSSSs}
```


## Task analysis

It's pretty clear that we're dealing with Bacon Cipher just instead of A/B or 0/1 we have S and s.

## Solution

We can change the input into more classic version:

```python
    ct = 'sSsSSsSSssSSsSsSsSssSSSSSSSssS{SSSsSsSSSsSsSSSsSSsSSssssssSSSSSSSsSSSSSSSSsSSsssSSssSsSSSsSSsSSSSssssSSsssSSsSSsSSSs}'
    ct = ct.replace('S', '0').replace('s', '1')
    print(ct)
```

And drop into cyberchef https://gchq.github.io/CyberChef/#recipe=Bacon_Cipher_Decode('Complete','0/1',false)&input=MTAxMDAxMDAxMTAwMTAxMDEwMTEwMDAwMDAwMTEwezAwMDEwMTAwMDEwMTAwMDEwMDEwMDExMTExMTAwMDAwMDAxMDAwMDAwMDAxMDAxMTEwMDExMDEwMDAxMDAxMDAwMDExMTEwMDExMTAwMTAwMTAwMDF9

and we get `UTFLAG{CRISPYBACONCIPHER}`
