# Mix Mix (re, 361p, 26 solved)

In the challenge we get an ELF [binary](mixmix) and `[output](out.txt).
The goal is to figure out inputs which would produce provided output.

## Analysis

The main is just:
```c
  printf("Enter text:");
  __isoc99_scanf("%s",user_input);
  len = strlen(user_input);
  if (0x20 < (int)len) {
    printf("too long!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  buffer = (char *)malloc(0x80);
  encrypt(user_input,buffer);
  outfile = fopen("out.txt","w");
  fprintf(outfile,buffer,"%s");
  fclose(outfile);
```

So we need to provide up to 32 characters to encrypt.

The encryption function is:

```c
  create_shuffled_array();
  create_some_consts();
  extract_input_bits(input);
  shuffle_input_bits();
  shuffle_input_bits_more();
  combine_shuffled_bits(encrypted_output);
  create_output(encrypted_output,outbuffer,0x20);
```

### create_shuffled_array

This function looks a bit like RC4 initialization:

```c
undefined8 create_shuffled_array(void)

{
  uint random;
  int i;
  
  srand(0xdefea7);
  i = 0;
  while (i < 0x100) {
    shuffled_numbers[i] = i;
    i = i + 1;
  }
  i = 0;
  while (i < 0x100) {
    random = rand();
    swap(shuffled_numbers + i,shuffled_numbers + (int)(random & 0xff));
    i = i + 1;
  }
  return 0;
}
```

It basically creates an array with numbers 0..255 and then randomly (but with static seed) swaps pairs.

### create_some_consts

As name suggests, this function simply takes the above shuffled array and creates some constants.
It's really not important for us what exactly is there.

### extract_input_bits

As name would suggest, this function simply splits our input into separate bits and stores in an array at `00302440`.
This is `uint[256]` so each bit is stored as separate `uint` in this array.

```c
undefined8 extract_input_bits(char *input)

{
  size_t len;
  int i;
  int j;
  int single_byte;
  
  i = 0;
  while( true ) {
    len = strlen(input);
    if (len <= (ulong)(long)i) break;
    single_byte = (int)input[i];
    j = 0;
    while (j < 8) {
      input_bits[i * 8 + j] = single_byte & 1;
      single_byte = single_byte >> 1;
      j = j + 1;
    }
    i = i + 1;
  }
  return 0;
}
```
### shuffle_input_bits

This function uses the shuffled numbers array to shuffle our input bits around.
It basically moves bit from index `k` to index `shuffled_numbers[k]`.
Notice that bits are not combined in any way, they are only permutated.

```c
undefined8 shuffle_input_bits(void)

{
  int i;
  int j;
  int k;
  
  i = 0;
  while (i < 4) {
    j = 0;
    while (j < 8) {
      k = 0;
      while (k < 8) {
        shuffled_input_bits[(long)k + ((long)j + (long)i * 8) * 8] =
             input_bits[shuffled_numbers[k + (j + i * 8) * 8]];
        k = k + 1;
      }
      j = j + 1;
    }
    i = i + 1;
  }
  return 0;
```

### shuffle_input_bits_more

Function a bit similar to the one above, it takes our already shuffled bits, and shuffles them even more, this time moving from index `k` to index `some_consts[k][0]+some_consts[k][1]`.
Again notice that bits are not combined in any way, they are only permutated.


```c
undefined8 shuffle_input_bits_more(void)

{
  int i;
  int j;
  int k;
  
  i = 0;
  while (i < 4) {
    j = 0;
    while (j < 8) {
      k = 0;
      while (k < 8) {
        shuffled_input_bits2[(long)k + ((long)j + (long)i * 8) * 8] =
             shuffled_input_bits
             [(long)some_consts[((long)k + (long)j * 8) * 2 + 1] +
              ((long)some_consts[((long)k + (long)j * 8) * 2] + (long)i * 8) * 8];
        k = k + 1;
      }
      j = j + 1;
    }
    i = i + 1;
  }
  return 0;
}
```

### combine_shuffled_bits

This function simply takes our shuffled bits and combines them back to whole bytes.
It takes bit, shifts left to put the bit in correct position, and adds this all together.

```c
undefined8 combine_shuffled_bits(int *combined_bits)

{
  int i;
  int j;
  int k;
  int sum;
  
  i = 0;
  while (i < 4) {
    j = 0;
    while (j < 8) {
      sum = 0;
      k = 0;
      while (k < 8) {
        sum = sum + (shuffled_input_bits2[(long)(7 - k) + ((long)j + (long)i * 8) * 8] <<
                    ((byte)k & 0x1f));
        k = k + 1;
      }
      combined_bits[j + i * 8] = sum;
      j = j + 1;
    }
    i = i + 1;
  }
  return 0;
}
```

### create_output

This function takes the combined shuffled bits from our input, performs XOR with generated keystream and puts in the output file.
The keystream generation again looks a bit like RC4 initialization.

```c
  defenit = 32767020166964548;
  j = 0;
  while (j < 0x100) {
    another_consts[j] = j;
    j = j + 1;
  }
  local_434 = 0;
  j = 0;
  while (j < 0x100) {
    iVar2 = another_consts[j];
    tmp = strlen(defenit);
    iVar2 = iVar2 + local_434 + (int)defenit[(ulong)(long)j % tmp];
    uVar1 = (uint)(iVar2 >> 0x1f) >> 0x18;
    local_434 = (iVar2 + uVar1 & 0xff) - uVar1;
    swap(another_consts + j,another_consts + local_434);
    j = j + 1;
  }
  j = 0;
  local_434 = 0;
  i = 0;
  while (i < len) {
    j = j + 1U & 0xff;
    uVar1 = (uint)(another_consts[j] + local_434 >> 0x1f) >> 0x18;
    local_434 = (another_consts[j] + local_434 + uVar1 & 0xff) - uVar1;
    swap(another_consts + j,another_consts + local_434);
    uVar1 = (uint)(another_consts[j] + another_consts[local_434] >> 0x1f) >> 0x18;
    outbuffer[i] = (byte)combined_shuffled_bits[i] ^
                   (byte)another_consts
                         [(int)((another_consts[j] + another_consts[local_434] + uVar1 & 0xff) -
                               uVar1)];
    i = i + 1;
  }
```

What we really care here about is:

```c
outbuffer[i] = (byte)combined_shuffled_bits[i] ^(byte)another_consts[(int)((another_consts[j] + another_consts[local_434] + uVar1 & 0xff) -uVar1)]
```

So the output value is just XOR of a byte from combined_shuffled_bits and some generated value.

## Solution

As the reader could notice, we glossed over the algorithm for generating the consts in the memory.
This is because we have no intention of reversing and re-writing this at all.
Instead we want to use debugger to dump the values we're interested in.

Let's think what do we need to recover the flag:

We know the output, and we can use debugger to dump the last XOR keystream values, and this should give us the `combined_shuffled_bits` we need.
Now we need to somehow go from this, back to the input.
We can split those `combined_shuffled_bits` again into bits, arriving at `shuffled_input_bits2`.
Now in order to know what input can generate such `shuffled_input_bits2` we need to know the permutation induced by the bits shuffling functions.

### Recover XOR keystream

Let's start with the easy part, dumping the XOR keystream at the very end.
We can put a breakpoint at `08000d8b` right before the XOR, and at this point `rcx` holds the value we're xoring with.

We can do that with a simple gdb script:

```python
import gdb
import codecs
import string
gdb.execute("break *0x08000d8b") # before xor
outfile = open("xors.txt",'w')
gdb.execute('r <<< $(python -c "print(\'A\'*32)")')
res = []
for i in range(32):
    rcx = gdb.parse_and_eval('$rcx')
    print(rcx)
    res.append(int(rcx))
    gdb.execute('c')
outfile.write(str(res))
outfile.close()
```

This way we recover `[247, 162, 130, 73, 139, 252, 234, 40, 142, 146, 75, 134, 81, 115, 215, 169, 165, 169, 56, 234, 105, 163, 139, 231, 172, 23, 9, 106, 139, 191, 253, 21]`

### Recover bits shuffling

We made an observation before, that bits are only shuffled, and never combined in any way, they only get permutated.
This means we always just move bit from position x to position y.

The idea is that we could supply input with just one bit lighted, and observe with debugger the state of `shuffled_input_bits2` after `shuffle_input_bits_more` and from that deduce where our bit was moved.

Sadly in reality it gets a bit more complex, because we can't supply just any values due to how the input is read.
For example input with only 5th bit lighted is 32 so a `space` character, and `scanf("%s")` won't like that.
There were also some issues with sending nullbytes.

This complicated the solution a bit, but the general idea stayed the same.

1. We break at `0800121a` after the bits were combined into bytes (we could earlier, but it doesn't really matter).
2. We start by sending input with just `chr(1)`
3. We look at the memory and examine all 32 combined bytes
4. If some `k-th` byte is not `0`, then our input bit provided a change there
5. We extract the `m` position of the bit
6. We save the information that input bit 0 on byte 0 is placed at byte `k` on bit `m`

Now we could move forward by sending `chr(0b10)` but to avoid issue with `chr(32)`, instead we send `chr(0b11)`, so a new bit, and bit we just tested before. 
We remember all changes introducted by previous bits, and we can remove them before we start looking for new changes.

This works fine for the first character, but the second one again proves to be an issue, because we can't just send `chr(0)+chr(X)` for some reason.
Because of that we decided to pad the input with `chr(1)`.
However, this means that the bit change from sending `chr(1)` as previous bytes, will always be visible in the outputs.
We need to account for that and remember which bits are changed by those `chr(1)` paddings, and remove this change before we look for changes introduced by bit we're testing.

In the end we come up with:

```python
import gdb
import codecs
import string
gdb.execute("break *0x0800121a") # after combined bits
outfile = open("outbits.txt",'w')
inferiors = gdb.inferiors()[0]
ones = []
for i in range(32):
    known = [0 for _ in range(32)]
    test = 0
    new_ones = ones[:]
    for j in [0,1,2,3,4,5,6,7]: # input will be printable, so no need for high bit
        # add padding with chr(1) for characters we already know
        skips = "+".join(["\'\'"]+["chr(1)" for _ in range(i)])
        test += 1<<j
        cmd = 'r <<< $(python -c "print '+skips+'+chr('+str(test)+')")'
        gdb.execute(cmd)
        rax = gdb.parse_and_eval('$rax')
        
        for outbyte in range(32):
            m = inferiors.read_memory(rax+(outbyte*4), 4).tobytes()
            val = int.from_bytes(m, 'little')
            # remove changes introduced by previous bits
            change = val^known[outbyte]
            known[outbyte] = val
            
            # remove the possible change introduced by chr(1) padding
            for one_pos, one_change in ones: 
                if one_pos == outbyte and (change&one_change)!=0:
                    change ^= one_change
            
            if change != 0:
                binary = bin(change)[2:].zfill(8)[::-1]
                position = binary.index('1')
                outfile.write(str((i,j,outbyte,position))+'\n')
                print(i,j,outbyte,position)
                if j == 0: # chr(1)
                    new_ones.append((outbyte, change))
    ones = new_ones
outfile.close()
```

After a moment we get back with [result](outbits.txt), eg:

```
(0, 1, 8, 6)
```

This tells us that bit 1 in input byte 0 is placed in output byte 8 in bit 6.

### Combining the flag

Now we have all information necessary to recover the flag.
We first deXOR the output using the XOR keystream we dumped:

```python
    target = open("out.txt", 'rb').read()
    xors = [247, 162, 130, 73, 139, 252, 234, 40, 142, 146, 75, 134, 81, 115, 215, 169, 165, 169, 56, 234, 105, 163, 139, 231, 172, 23, 9, 106, 139, 191, 253, 21]
    expected_permutated = xor(map(ord, target), xors)
```

Now we use our `outbits.txt` to create a permutation mapping:

```python
    permutation_mapping = open("outbits.txt", 'rb').read()
    permutation = defaultdict(dict)
    for line in permutation_mapping.split("\n"):
        if line:
            src_byte, src_bit, target_byte, target_bit = eval(line)
            permutation[target_byte][target_bit] = (src_byte, src_bit)
```

We now have dict that can tell us which bit in which byte we need to set to 1 in order to get a bit 1 on given byte and bit position.

With this we can iterate through bytes of expected_permutated, extract positions where bits are 1 for each byte and use the permutation mapping to create the appropriate input:

```python
    flag = [0 for _ in range(32)]
    for i, byte in enumerate(expected_permutated):
        permutations_for_byte = permutation[i]
        binary = bin(byte)[2:].zfill(8)[::-1]
        for bit in range(len(binary)):
            if binary[bit] == '1':
                src_byte, src_bit = permutations_for_byte[bit]
                flag[src_byte] ^= (1 << src_bit)
    print("".join(map(chr, flag)))
```

From this we get `Defenit{m1x_r4nd_c0lumn_r0w_rc4}`
