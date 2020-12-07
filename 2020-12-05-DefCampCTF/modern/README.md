# secret-reverse (re, 50p, 75 solved)

## Description

```
This should rock your life to the roots of your passwords.

Flag format: CTF{sha256}
```

In the task we get a [android app](modern-login.apk).

## Task analysis

We proceed with dropping the binary into BytecodeViewer to see what's inside.
It seems a bit weird, there is some native dependency and some Kivy glue code, some tar library and some library for resource extraction.
The task description suggests some `rockyou` password cracking, but we did not see anything like that at all...

In the app resources there is also some weird mp3 file.

### Native code

Native libSDL code seems to be doing some python-related stuff, nothing which would look remotely interesting.

### Kivy

There is a lot of glue code there to run python code, so our guess is that we're supposed to find this python.

### mp3

If we do binwalk on this mp3 we get:

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             gzip compressed data, maximum compression, has original file name: "private.mp3", last modified: 2020-11-04 14:28:05
26469         0x6765          Zip archive data, at least v2.0 to extract, compressed size: 8589, uncompressed size: 18246, name: ftplib.pyc
74665         0x123A9         Zip archive data, at least v2.0 to extract, compressed size: 9399, uncompressed size: 22931, name: threading.pyc
323482        0x4EF9A         Zip archive data, at least v2.0 to extract, compressed size: 19940, uncompressed size: 51296, name: _pyio.pyc
355782        0x56DC6         Zip archive data, at least v2.0 to extract, compressed size: 7147, uncompressed size: 13803, name: zipimport.pyc
380117        0x5CCD5         Zip archive data, at least v2.0 to extract, compressed size: 18736, uncompressed size: 57351, name: pickletools.pyc
2333666       0x239BE2        Zip archive data, at least v2.0 to extract, compressed size: 11662, uncompressed size: 25143, name: http/client.pyc
```

It gets even better if we just do `file`:

```
private.mp3: gzip compressed data
```

We can actually unpack it and we find the python codes we were missing!

## Reversing the python source

We now have the [main.py](main.py).
We can do some renames and the whole crypto code collapses to:

```python
def repeated_xor(byt):
    q = b'viafrancetes'
    f = len(q)
    return ''.join([chr(ord(c) ^ ord(q[i % f])) for i, c in enumerate(byt)])


def decode(s):
    y = repeated_xor(s.encode())
    return y.decode("utf-8")
```

We can decode first two blobs with:

```python
kv = decode("|:\x02\x14\x17\x04\x00YoTESV\x00\x0f9\x11\r\x0f\x10\x16NE\x07\x13\x11\x15lRANC(0)\x12\x14\x0c\r\\xANCETESV\x1d\x04\x1e\x06[ND(\x1b\x01\x16\x04\x07A*\x1d\x06\x07\rB~ESVIAFRA\x08\x0c\x0b\x00:\x00\x02\x10\r\x03HAI+WSoSVIAFRAN\x13\n\x07:\x1b\x1f\x07\x15\\R\x1aI\x00\x00\x1a\x11\x16\x046\x19AHA^MRXET\x15\x0c\x0f\x12\x17\x131\x1aBNECXQ\x1clRANC(01\x16\x0e\x1d'\x0f\x17\r\nYoTESVIAFR\x08\nYE\x00\x00\x0b\x02cAFRANCET\r\x1a\x18\x1d>\x12\x17\x19\x1aYES \x1d\x02\x0c\x13F\x0b\x0e\x1bC\x15\x15\x16\x00\x01\x06\x13\x02UkNCETESVI\t\x03\x1e\x11\x0b\x11:\x00\x00\x0b\x02SAA4\x0e\x1c\x04\n\x00E\n\x19\x1c\x13F\x02\x00\x1d\x10\x12\x1b\x17\x17INkFRANCETE\x1b\x13\x05\x11\x03\x00>\x1a\x06\x1d\x00:\x1e\x19\r\x04\\RC\x01\r:\x12\n\x10\x03\x1aCFxANCETESV\x19\x0e\x15-\t\x07\r\x11NE\x08Q\n\x04\x08\x06\x04\x1c<\x1dS_SFGTJRF\r\x06\x0b\x00\x00\x01)\x10F\\RQ@W\x18~ESVIAFRA\x1d\n\x1f\x11:\x1b\x1f\x07\x159\n[N-\n\x1a\x00yVIAFRANC\x12\x1d\x01\x07\x1eSAUBQdCETESVIA\x0f\x11\x0e\x00<\x17\x1d\x02\x1b\x02SAD\x13\x02\r\x0c\x10\x1a\x11^\x05\x0c\x00\x14\x11\tLiETESVIAF\x00\x04\x1f\x16\x0c\x06\x00\x17LI5\x14\x07\x04dCETESVIAlRANC(07\x16\x15\x1d\x00\x08\x15\r\x0b%\t\x15\x111\x03\x1d\x15\t\x1c[dCETESVIA\x12\x17\x19\x1aYES6\x06\x14\x04\x08\x12UkNCETESVI\x11\t\x01>\x06\n\x0b\x00_S\rN\x02\x03\x1c\x15\x0b\x11:\x0cBIVYOS^AI\x00\x00\x1a\x11\x16\x046\x18AHA^MV\toSVIAFRAN\x0c\x0b+\x15\x01\x13\x1a\x12\\xANCETESVIAFR\x00\x1e\x13K\x15\x10\x07\x1eAHlRANCETESVIAFxANCE9!?\x17\x0b\x04\nHkNCETESVI\x15\x03\n\x15TCBSoSVIAFRAN\n\x01NE\x00\x1e\x06\x16lRANCETES\x06\x06\x129\x1a\x08\x00\x17_T\x1eT\x15\x0c\x0f\x12\x17\x131\x1bBNEBFGQJRF\r\x06\x0b\x00\x00\x01)\x10F\\RP^MW\to")
i = decode('R[\x18BCSJ\x10)D+2\x01]6>(\x05\x16R<:T%\x04(X\x0e\x07O\x1aS\x065\x0f"?1\x07$\x02 \nS\x07\x1e,*\'\x1cP%\x166=\x11T3/\x1a')
print(kv)
print(i)
```

And we get:

```
Screen:
    in_class: text
    MDLabel:
        text: 'Modern Login'
        font_style: 'H2'
        pos_hint: {'center_x': 0.7, 'center_y': 0.8}
    MDTextField:
        id: text
        hint_text: 'Enter you password'
        helper_text: 'Forgot your password?'
        helper_text_mode: "on_focus" 
        pos_hint: {'center_x': 0.5, 'center_y': 0.4}
        size_hint_x: None
        width: 300
        icon_right: "account-search"
        required: True
        
    MDRectangleFlatButton:
        text: 'Submit'
        pos_hint: {'center_x': 0.5, 'center_y': 0.3}
        on_press:
            app.auth()
            
    MDLabel:
        text: ''
        id: show
        pos_hint: {'center_x': 10.0, 'center_y': 10.2}
```

And:

```
$2y$12$sL0NAw4WXZdx1YN1VrA9hu.t0cAjQIXfBpAd0bjIYQu1CdWSr1GJi
```

Now there is some bcrypt check on this last value, but we can just skip it and decrypt the last blob:

```python
g = "\x15\x1d\x07\x1dATX\x00P\x11RJG\r\x04VJW_S\x07L\x00J\x15\x0bQV\x13WZ\x07TB\x06A\x15\x0f\x02T\x10\x04^S\x07EV@\x10\r\x07\x07GPW[QFUAG]XVK\x02\rR\x18"
flag = decode(g)
print(flag)
```

And we get: `ctf{356c5e791de08610b8e9cb00a64d16c2cfc2be00b133fdfa5198420214909cc1}`
