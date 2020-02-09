# RSA is easy 2 (crypto, 50p, 157 solved)

This challenge looks very similar to the first one, but the twist is that we don't know the public key.

Despite RSA in the name, what we really have here is simply a monoalphabetic substitution cipher.
We start with translating long numbers into letters: 
```python
x = 0
charset = string.uppercase + string.lowercase
mapping = {}
for uniq in set(encflag):
    mapping[uniq] = charset[x]
    x += 1
result = "".join([mapping[c] for c in encflag])
print(result)
``` 

From this we get a nice:

```
LXaPMBMEOCMBPMDFbbaIaMBPMHXaMaOZbTMdWCeMBMUacBCaUMEXOHMBMVabBacaUMEOCMOMVZBbbBOPHMaPDZTfHBFPMCDXaAaJMOMCBAfbaMfCaQUFZOPUFAMPQAVaZMCHZaOAMEOCMOUUaUMHFMHXaMfbOBPHaKHMCHZaOAMHFMDZaOHaMDBfXaZHaKHJMHXBCMEFQbUMCaaABPIbTMHXEOZHMOPTMYZaRQaPDTMOPObTCBCMFYMHXaMDBfXaZHaKHeMOPUMEFQbUMVaMQPDZODNOVbaMacaPMHFMHXaMAFCHMZaCFQZDaYQbMIFcaZPAaPHMBPHabbBIaPDaMOIaPDBaCJMBMYabHMCFMCAQIMOVFQHMATMODXBacaAaPHJMTaOZCMbOHaZeMBMUBCDFcaZaUMHXBCMCOAaMCDXaAaMBPMCacaZObMBPHZFUQDHFZTMDZTfHFIZOfXTMHaKHCMOPUMHQHFZBObMfOfaZCJMXFEMPBDaJMFHXaZMDZTfHFIZOfXaZCMXOUMHXFQIXHMFYMHXaMCOAaMCDXaAaJMQPYFZHQPOHabTeMHXaMCDXaAaMEOCMfZaCaPHaUMOCMOMCBAfbaMXFAaEFZNMOCCBIPAaPHMFPMXFEMHFMQCaMabaAaPHOZTMDZTfHOPObTHBDMHaDXPBRQaCMHFMHZBcBObbTMDZODNMBHJMCFMAQDXMYFZMATMVZBbbBOPHMCDXaAaJMYZFAMHXBCMXQAVbBPIMaKfaZBaPDaMBMbaOZPaUMXFEMaOCTMBHMBCMHFMYObbMBPHFMOMYObCaMCaPCaMFYMCaDQZBHTMEXaPMUacBCBPIMOPMaPDZTfHBFPMObIFZBHXAJMAFCHMfaFfbaMUFPSHMZaObBGaMXFEMYBaPUBCXbTMUBYYBDQbHMBHMBCMHFMUacBCaMOPMaPDZTfHBFPMObIFZBHXAMHXOHMDOPMEBHXCHOPUMOMfZFbFPIaUMOPUMUaHaZABPaUMOHHODNMVTMOMZaCFQZDaYQbMFffFPaPHJMXaZaMBCMHXaMYbOIJMEXaPMBHMDFAaCMHFMDZTfHFMFZMDOZfaHMPacaZMZFbbMTFQZMFEP
```

Now we proceed with tedious manual work of reconstructing the key.
We can try to use some statistics:

```python
print(Counter(result))
```

And we get:

```python
Counter({'M': 177, 'a': 123, 'H': 83, 'O': 66, 'B': 64, 'P': 61, 'F': 60, 'Z': 59, 'C': 57, 'b': 44, 'X': 43, 'D': 39, 'A': 31, 'U': 28, 'T': 26, 'f': 25, 'Q': 24, 'E': 17, 'I': 16, 'Y': 16, 'J': 12, 'c': 11, 'V': 9, 'K': 5, 'N': 4, 'e': 4, 'R': 2, 'G': 1, 'L': 1, 'S': 1, 'W': 1, 'd': 1})
```

Sadly the text is short, and doesn't really match english letter statistics very well, but already first few letters help us:

```python
real_mapping = {'M': ' ', 'a': 'e', 'H': 't', 'O': 'a'}
print("".join([real_mapping[c] if c in real_mapping else "?" for c in result]))
```

We can now use the fact that english has for example only 2 words with a single letter -> `I` and `a`.
We already matched `a` so the remaining single letters have to be `I`.
Then we can also guess that `t?e` is most likely `the`, and add another letter, same with `t?` which has to be `to`.

From this we find more familiar words like `othe?` which needs to be `other`, `thi?` as `this` and `ho?` as `how`.

At this point we have so many familiar words that we can easily recover full mapping:

```python
real_mapping = {'M': ' ', 'a': 'e', 'H': 't', 'O': 'a', 'B': 'i', 'X': 'h', 'F': 'o', 'Z': 'r', 'C': 's', 'E': 'w', 'P': 'n', "L": 'W', "A": "m", "D": "c",
                    "b": "l", "T": "y", "f": "p", "V": "b", "c": "v", "U": "d", "Q": "u", "I": "g", "K": "x", "J": ".", "e": ",", "d": "7", "W": "0", "Y": "f",
                    "R": "q", "N": "k"}
```

And with is the message:

```
When i was in college in the early 70s, i devised what i believed was a brilliant encryption scheme. a simple pseudorandom number stream was added to the plaintext stream to create ciphertext. this would seemingly thwart any frequency analysis of the ciphertext, and would be uncrackable even to the most resourceful government intelligence agencies. i felt so smug about my achievement. years later, i discovered this same scheme in several introductory cryptography texts and tutorial papers. how nice. other cryptographers had thought of the same scheme. unfortunately, the scheme was presented as a simple homework assignment on how to use elementary cryptanalytic techniques to trivially crack it. so much for my brilliant scheme. from this humbling experience i learned how easy it is to fall into a false sense of security when devising an encryption algorithm. most people don?t reali?e how fiendishly difficult it is to devise an encryption algorithm that can withstand a prolonged and determined attack by a resourceful opponent. here is the flag. when it comes to crypto or carpet never roll your own
```

And so the flag is `HackTM{when_it_comes_to_crypto_or_carpet_never_roll_your_own}`

