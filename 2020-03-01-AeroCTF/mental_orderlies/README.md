# Mental adventure: call the orderlies (PIC, 490p, 9 solved)

This is another PIC challenge to work on.
We have the same kind of [PIC binary](Smth.HEX), and we can again load it to ghidra selecting PIC16F as architecture.
Apart from the binary we also get a [video](EncryptedMessage.mp4).

We can see there the display showing some characters.
We can scrap those to get `{W7C0RC9JERQ2RW42J{VUXUVFS`.

The code is surprisingly similar to the one from `beginning`.
We have almost identical loop, but this time there are 2 changes:

```c
  DAT_DATA_0024 = param_1;
  while( true ) {
    DAT_DATA_0025 = FUN_CODE_0f00(DAT_DATA_0024);
    DAT_DATA_0020 = -0x56 - (DAT_DATA_0025 ^ 0x87);
    FUN_CODE_0016();
    FUN_CODE_000e();
    if (DAT_DATA_0025 == 0) break;
    DAT_DATA_0024 = DAT_DATA_0024 + '\x01';
  }
  return DAT_DATA_0025;
```

First difference is that result of `FUN_CODE_0f00` functions is now modified by `DAT_DATA_0020 = -0x56 - (DAT_DATA_0025 ^ 0x87);` before it reaches `FUN_CODE_0016`.
This we can easily invert by:

```python
0xFF & (-(val + 0x56) ^ 0x87)
```

Second twist comes from the `FUN_CODE_0f00` function itself.
In the first problem this function was pretty much sending plaintext flag data.
Here it got patched and returns only 0.

So we need to figure out the values supplied by this function by looking at the display.

It took us a while to understand how `FUN_CODE_0016` is connected with the display, but finally we noticed that on the video the display has two sets of input bits (top and bottom), and the function is doing things like:

```asm
                             LAB_CODE_0028                                   XREF[1]:     CODE:0022 (j)   
       CODE:0028 20  08           MOVF       DAT_DATA_0020 ,w                                 = ??
       CODE:0029 09  3a           XORLW      #0x9
       CODE:002a 03  1d           BTFSS      STATUS ,#0x2
       CODE:002b 31  28           GOTO       LAB_CODE_0031
       CODE:002c 36  30           MOVLW      #0x36
       CODE:002d 87  00           MOVWF      FSR1H
       CODE:002e 88  30           MOVLW      #0x88
       CODE:002f 88  00           MOVWF      BSR
       CODE:0030 75  29           GOTO       LAB_CODE_0175
```

Notice that the decompiler lies a bit here, because it only shows the fact that `BSR` is set, and shows this as return value of the function.
In reality each block stores 2 outputs -> `FSR1H` and `BSR`, exactly as many as the display expects to get.

We could type down the bits flashing for every character shown on display, convert them to numbers and then look for given combinarion in `FUN_CODE_0016` but that's extremely tedious.
Instead we decided to use what we learned from the first binary.
From the first binary we know what value is returned by `FUN_CODE_0f00` when we want to display certain character, eg `0xa` for `A`.

We can therefore generate the whole mapping from the first binary:

```
0 0x00 0x3f 0x44
1 0x01 0x18 0x04
2 0x02 0x36 0x88
3 0x03 0xfc 0x08
4 0x04 0x19 0x88
5 0x05 0xed 0x88
6 0x06 0xef 0x88
7 0x07 0x38 0x00
8 0x08 0xff 0x88
9 0x09 0xfd 0x88
A 0x0a 0xfb 0x88
B 0x0b 0x3c 0x2a
C 0x0c 0xe7 0x00
D 0x0d 0x3c 0x22
E 0x0e 0xe7 0x80
F 0x0f 0xe3 0x80
G 0x10 0xef 0x08
H 0x11 0xdb 0x88
I 0x12 0xe4 0x22
J 0x13 0xde 0x00
K 0x14 0x03 0x94
L 0x15 0xc7 0x00
M 0x16 0xdb 0x05
N 0x17 0xdb 0x11
O 0x18 0xff 0x00
P 0x19 0xf3 0x88
Q 0x1a 0xff 0x10
R 0x1b 0xf3 0x98
S 0x1c 0xed 0x88
T 0x1d 0xe0 0x22
U 0x1e 0xdf 0x00
V 0x1f 0xc3 0x44
W 0x20 0x1b 0x50
Y 0x22 0x00 0x25
Z 0x23 0xe4 0x44
{ 0x24 0x00 0xa2
} 0x25 0x00 0x2a
_ 0x26 0x04 0x00
```

The way to read this table, is that if display shows for example `V` it means the input was `0x1f` and `FSR1H` and `BSR` were set to `0xc3` and `0x44`.

X was for some reason missing, so we had to get this one character the hard way.

We turne this into map:

```python
mapping = {}
for line in data.split("\n"):
    x = line.split(" ")
    mapping[x[0]] = x[1]
```

Now for character we will know the value that was passed.

Notice that `FUN_CODE_0016` actually does not look the same!
The `FSR1H` and `BSR` are the same in each consecutive block, but the conditions are shuffled.
So we need one more mapping, which we can simply generate by running `print(map(lambda x:int(x,16),re.findall("==\s*(.*)\)", data)))` over the ghidra decompiled function.

This gives us `mapping2 = [7, 2, 9, 4, 3, 12, 5, 14, 1, 16, 17, 4, 11, 6, 21, 8, 23, 18, 25, 20, 13, 28, 15, 30, 0, 24, 19, 26, 35, 22, 37, 32, 33, 34, 27, 36, 29, 38]`

This means for example that if the `mapping` returns us value `k` the real input passed to `FUN_CODE_0016` was `mapping2[k]`.

Now we need to decode the flag:

```python
def decode(val):
    return 0xFF & (-(val + 0x56) ^ 0x87)

out_mapping = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_"
data = '{W7C0RC9JERQ2RW42J{VUXUVFS'

res = ''
for c in data:
    if c is not 'X':
        res += out_mapping[decode(mapping2[int(mapping[c], 16)])]
    else:
        res += '?'
print(res)
```

And we get `AERO{NOTHING_NEW_HAD2?2D}0`

Keep in mind we were missing mapping for `X` but we got it directly from the video, and it was mapping to `F` so the flag is `AERO{NOTHING_NEW_HAD2F2D}`
