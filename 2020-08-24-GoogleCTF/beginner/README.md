# Beginner (re, 50p, 482 solved)

## Description

In the task we get a classic 64bit ELF [linux binary](beginner) which checks the flag for us.

## Static analysis

### Decompiled code

The code we get from Ghidra is pretty short, but also a bit weird:
```c
ulong main(void)
{
  int cmp_result;
  uint cmp_result2;
  int shuffled_input [4];
  undefined auVar1 [16];
  char user_input [16];
  int decrypted_flag [4];
  
  printf("Flag: ");
  __isoc99_scanf("%15s",user_input);
  shuffled_input = pshufb(user_input,SHUFFLE);
  auVar1 = CONCAT412(SUB164(shuffled_input >> 0x60,0) + ADD32[3],
                     CONCAT48(SUB164(shuffled_input >> 0x40,0) + ADD32[2],
                              CONCAT44(SUB164(shuffled_input >> 0x20,0) + ADD32[1],
                                       SUB164(shuffled_input,0) + ADD32[0]))) ^ XOR;
  decrypted_flag[0] = SUB164(auVar1,0);
  decrypted_flag[1] = SUB164(auVar1 >> 0x20,0);
  decrypted_flag[2] = SUB164(XOR >> 0x40,0);
  decrypted_flag[3] = SUB164(XOR >> 0x60,0);
  cmp_result = strncmp(user_input,(char *)decrypted_flag,0x10);
  if (cmp_result == 0) {
    cmp_result2 = strncmp((char *)decrypted_flag,EXPECTED_PREFIX,4);
    if (cmp_result2 == 0) {
      puts("SUCCESS");
      goto LAB_00101112;
    }
  }
  cmp_result2 = 1;
  puts("FAILURE");
LAB_00101112:
  return (ulong)cmp_result2;
}
```

It's also not particularly accurate, but we can get some basic info from it:

- The input flag we provide is supposed to have 15 characters
- The flag starts with `CTF{` prefix
- Our input is somehow transformed and the result is compared again with the input

### Disassembly

If we look at disassembly of this function, it's actually much cleaner.
Especially the part which decompiled to all those `CONCAT412` and `SUB164`.
Assembly code is just:

```asm
001010ae 66  0f  6f       MOVDQA     XMM0 ,xmmword ptr [RSP ]=>user_input
         04  24
001010b3 48  89  ee       MOV        RSI ,RBP
001010b6 4c  89  e7       MOV        RDI ,R12
001010b9 ba  10  00       MOV        EDX ,0x10
         00  00
001010be 66  0f  38       PSHUFB     shuffled_input[0] ,xmmword ptr [SHUFFLE ]         = 
         00  05  a9 
         2f  00  00
001010c7 66  0f  fe       PADDD      shuffled_input[0] ,xmmword ptr [ADD32 ]           = 
         05  91  2f                                                                   = null
         00  00
001010cf 66  0f  ef       PXOR       shuffled_input[0] ,xmmword ptr [XOR ]             = 
         05  79  2f 
         00  00
001010d7 0f  29  44       MOVAPS     xmmword ptr [RSP  + decrypted_flag[0] ],shuffled
         24  10
```

The idea is pretty simple:

- our input is loaded to `XMM0`
- it's then shuffled using constant `SHUFFLE` array
- then constant `ADD32` value is added
- finally it's xored with constant `XOR` value

Note that we have `xmmword ptr` everywhere, and this means everything is actually happening for 128-bit data slices at once!

However due to how mathematics work, we can actually consider those operations to be done on single bytes, but it might cause issues with carry-over.
To sum up, the flag is passed via simple `out_byte = (flag_byte+const1) ^ const2` and initially flag characters are shuffled.

## Solution

Since we know that encryption/decryption process is just `out_byte = (in_byte+const1) ^ const2` and we know that this has to match our initial input, we can easily invert this logic thanks to the shuffling!
Because the shuffle makes `out_byte` and `in_byte` to be different values, from different positions in the flag input buffer.

Constants are:

```
xor = map(ord, '76 58 B4 49 8D 1A 5F 38 D4 23 F8 34 EB 86 F9 AA'.replace(' ', '').decode("hex"))
add = map(ord, 'EF BE AD DE AD DE E1 FE 37 13 37 13 66 74 63 67'.replace(' ', '').decode("hex"))
shuffle = map(ord, '02 06 07 01 05 0B 09 0E 03 0F 04 08 0A 0C 0D 00'.replace(' ', '').decode("hex"))
```

### Example

Notice that at index 0 in shuffle table there is `2`, in add table `EF` and in xor table `76`
This means that:

```python
flag[0] == ((flag[2]+add[0]) ^ xor[0]) & 0xff
```

and thus:

```python
flag[0] == ((ord('F')+0xEF) ^ 0x76) & 0xff
```

We can run this and we get as expected value `67` so `C`!

### Full solver

The idea is to use this approach to uncover characters we don't know.
Notice for example that in shuffle table value `03` is somewhere in the middle - this means we could use a known 3rd flag character `{` to uncover this middle byte.
Hopefully the 4 chars we know will be enough to propagate all others.

We want to loop over the flag we know, and propagate every flag char we can:

```python
data = 'CTF{' + ''.join(chr(0xff) for i in range(12))
result = list(data)
for target_index in range(16):
    src_index = shuffle[target_index]
    known_char = result[src_index]
    if known_char != '\xff' and result[target_index] == '\xff':
        a = add[target_index]
        x = xor[target_index]
        val = ((ord(known_char) + a) ^ x)
        result[target_index] = chr(val % 256)
```

If we run this only once, it will propagate only 2 additional characters.
We need to run this at most 12 times, to uncover all the missing 12 characters, if each iteration would propagate only a single byte.
We could also include trailing `}` and nullbyte at the end, in case we didn't have enough, but it's just fine with only prefix.

### Carry issue

This code prints almost-perfect flag -> `CTF{S1NCf0rM3!}`.
The problem is that we're totally dismissing carry!
Addition and xor of some lower byte might have overflown and modified the upper byte.

But if we print out `val/256` we can see that there were only a handful and only by `1` so we can guess the right flag.
We can also place this broken flag into the binary and look under debugger at the flag generated for comparison.
Either way we get `CTF{S1MDf0rM3!}`
