# Elderly file (warmup/re, 100p, 53 solved)

In the challenge we get [ELF binary](encoder) and some [encrypted data](file.enc).

Looking at the binary it turns out it's python script turned into executable by some kind of pyinstaller-like software.
There is no point trying to reverse the binary, it's just python interpreter. 
We need to extract the `pyc` files inside.

Initial, unsuccessful, approach was to cut out PYZ archive from the binary and then use an extractor on that.
It's easy to find PYZ since it has `PYZ` magic, but for some reason the extractor was showing all stored modules except for `__main__`.
But now that we knew that all pyc files are stored there simply as `zlib streams`, we simply run `binwalk` on the binary, and then we went through all extracted zlib streams looking for main.
You can just grep for some strings you expect there, like `encoder.py` or `argv`.

Finally we found the [main pyc](main.pyc).
Then we tried to decompile it with uncompyle, but there were some issues with invalid magic, indicating weird python version, and with some instructions when we changed the magic.
Since the file is so small, we could probably just do ok with `dis.dis()`, but there was no need even for that.

If you look at strings inside the file we have:

```
__main__i
Usage: i
 <file-path>s
.enc(
lzsst
syst
__name__t
lent
argvt	
file_patht
exitt
encode_file(
encoder.pyt
<module>
```

Not much here, but there is one interesting thing -> `lzss` and `encode_file`.
It seems this is all that the main is doing, so let's try to invert this operation:

```python
import lzss
lzss.decode_file("file.enc", "file.hex")
```

And from this we get a [hex file](file.hex)

We could try to load this into ghidra and guess what kind of binary we're dealing with, but before that we can just do:

```python
data = open("file.hex", "rb").readlines()
for line in data:
    print(line[1:].strip().decode("hex"))
```

And from this we learn that it's some classic ELF x64, but we don't need any RE because there is plaintext flag `Aero{33d8b218a9961657b74c5036fe44527a02ce03c4da34f8a1cda5f2188c23a1b5}`
