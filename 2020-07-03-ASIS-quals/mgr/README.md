# Merry go round (re, 80p, 60 solved)

## Description

In the task we get a [binary](mgr) and [result](flag.enc).
The binary is a simple encryptor.
We run it and and it will encrypt `flag.txt` to `flag.enc`.

Ghidra becomes sad at this C++ binary, but fortunately it's again `every RE is a blackbox crypto if you're brave enough` kind of deals, and we're definitely brave!

At the start of the function some static constants are generated and random is seeded.
We don't really care about this, we focus on what happens with our input.
The interesting part is at:

```c
      begin_iter = begin();
      end_iter = end();
      while( true ) {
        has_next = has_next(&begin_iter,&end_iter,&end_iter);
        if (has_next == '\0') break;
        iterator = (char *)get_iter(&begin_iter);
        input_char = *iterator;
        some_xors((byte *)local_508,&input_char,&xored_input_char,1);
        xored_inputs_array[index] = xored_input_char;
        index = index + 1;
        next(&begin_iter);
      }
      wtf(0x10,0x20);
      open((char *)local_488,0x102e5b);
      flush();
      local_574 = rand();
      local_574 = local_574 % 10;
      randomized_xor(local_508,xored_inputs_array,(char *)output,(short)length,(char)local_574);
      operator<<<std--char_traits<char>>(local_488,output);
      close();
```

Those xor functions do stuff like:

```c
void some_xors(byte *param_1,char *keystream,char *output,ushort length)

{
  byte bVar1;
  byte bVar2;
  ushort index;
  
  bVar1 = *param_1;
  bVar2 = param_1[0x12];
  index = 0;
  while (index < length) {
    output[index] =
         keystream[index] ^ (byte)index ^ bVar2 ^ bVar1 ^
         *(byte *)((long)(0 % (uint)*(ushort *)(param_1 + 0x10)) + *(long *)(param_1 + 8));
    index = index + 1;
  }
  return;
}
```

and:

```c
void randomized_xor(byte *keystream,char *input,char *output,ushort length,byte random)

{
  byte bVar1;
  byte bVar2;
  ushort index;
  
  bVar1 = *keystream;
  bVar2 = keystream[0x12];
  output[length] =
       (byte)length ^ random ^
       *(byte *)((long)((int)((uint)length ^ (uint)(bVar2 ^ bVar1)) %
                       (uint)*(ushort *)(keystream + 0x10)) + *(long *)(keystream + 8));
  index = 0;
  while (index < length) {
    output[index] =
         (byte)index ^ input[index] ^ random ^
         *(byte *)((long)((int)((uint)(bVar2 ^ bVar1) ^ (uint)index) %
                         (uint)*(ushort *)(keystream + 0x10)) + *(long *)(keystream + 8));
    index = index + 1;
  }
  return;
}
```

What we can see here is that input values are used byte by byte in both cases!
This is convenient because it means we can just brute-force flag single byte at a time.

## Solution

### Beat the random

One small issue is the:

```c
local_574 = rand();
local_574 = local_574 % 10;
randomized_xor(local_508,xored_inputs_array,(char*)output,(short)length,(char)local_574);
```

It will xor output via some random and interfere with our brute force.
We need to get rid of this!

The easy trick is to compile:

```c
int rand(){
    return 9;
}
```

`gcc -shared -fPIC unrandom.c -o unrandom.so`

And then run the binary via `LD_PRELOAD=$PWD/unrandom.so ./mgr` and random will always have a fixed value.

Now we need to figure out which value, but this is easy, since random is taken `%10`.
We know flag format so we know the flag has to start with `ASIS`.
We can therefore encrypt `ASIS` using every possible value `0-9` and for one of them the encrypted flag prefix will match our output.

### Brute the flag

Now we can focus on the flag brute force.
There is nothing special here:

1. Put in the input file known prefix of the flag + random character from charset
2. Encrypt
3. Compare results with encrypted flag, if whole prefix matches then extend known prefix and start again. Otherwise test another char from charset.

```python
import codecs
import subprocess
import string

def main():
    flag = 'ASIS{'
    with codecs.open('flag.enc.orig','rb') as reference:
        target = reference.read()
        for index in range(len(target)-len(flag)):
            for c in string.ascii_letters + string.digits + string.punctuation:
                candidate = flag+c
                with codecs.open("flag.txt", 'wb') as f:
                    f.write(candidate)
                subprocess.call("LD_PRELOAD=./urandom.so ./mgr",shell=True)
                with codecs.open('flag.enc', 'rb') as e:
                    result = e.read()[len(flag)]
                    if result == target[len(flag)]:
                        flag = candidate
                        print(flag)
                        break
main()
```

After a moment we get:

`ASIS{Kn0w_7h4t_th3_l1fe_0f_thi5_wOrld_1s_8Ut_amu5em3nt_4nd_div3rsi0n_aNd_adOrnmen7}`