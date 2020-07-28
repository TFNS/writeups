# Baby RE (re, 50p, 314 solved)

In the task we get a [weird XML](babyrev.xml) which is some configuration for https://snap.berkeley.edu/snap/snap.html
We're too lazy to use such tools, and also best RE are just crypto blackboxes, so we scrolled through the XML and found:

```xml
<variable name="secret"><list struct="atomic" id="952">66,88,67,83,72,66,82,90,86,18,77,16,98,17,76,18,126,97,79,69,126,102,17,17,69,126,77,116,66,74,0,92</list></variable>
```

It looked promising, so we checked what would this ascii-decode into.
It was not a flag yet, but we figured that we know flag format `cybrics{XXX}` so we did some classic quick checks and:

```python
data = [66, 88, 67, 83, 72, 66, 82, 90, 86, 18, 77, 16, 98, 17, 76, 18, 126, 97, 79, 69, 126, 102, 17, 17, 69, 126, 77, 116, 66, 74, 0, 92]
string_data = "".join(map(chr, data))
print(xor_string("cybrics", string_data).encode("hex"))
```

And we got a bunch of `0x21`, so it seems every character is XORed with the same byte.
So we can do:

```python
print(xor_string(string_data, '\x21' * 100))
```

To get `cybrics{w3l1C0m3_@nd_G00d_lUck!}`
