# Latte (re, 154p, 27 solved)

## Description

In the task we get encryptor [binary](latte) and encryption [output](flag.latte)

The binary takes input and output file paths and also `key` parameter.
The output file is clearly longer than the input.

### Blackbox analysis

Some input characters gets nicely rewritten directly (eg. all capital letters), some characters are changes to some weird `text representation` (eg. all symbols and numbers) and also in random places we can notice weird chunks of our key parameter.

### Code analysis

#### main

From the `main` we can see:

```c
  len = strlen(argv[2]);
  if (len != 0x10) {
    puts("Key format is incorrect!");
    exit(0);
  }
```

So `key` needs to be 16 bytes long.

Rest of main is just:

```c
  input_file = fopen(argv[1],"rb");
  if (input_file == (FILE *)0x0) {
    puts("File can not be opened or there is no such file!");
    exit(0);
  }
  fseek(input_file,0,2);
  file_len = ftell(input_file);
  fseek(input_file,0,0);
  input_buffer = (char *)malloc(file_len + 1);
  fread(input_buffer,1,file_len,input_file);
  fclose(input_file);
  input_buffer[file_len] = '\0';
  outbuffer = calloc(file_len * 0x14,1);
  stage1(input_buffer,argv[2],outbuffer); // argv[2] == key
  local_2c = stage2(outbuffer,0,&final_outbuffer,0x400);
  outfile = fopen(argv[3],"w");
  fwrite(&final_outbuffer,1,0x400,outfile);
  fclose(outfile);
```

So the encryption is done via two function passes `stage1` which uses the `key` and then `stage2`.

#### stage1

Most important part of `stage1` is at the very start:

```c
  do {
    index_ = SEXT48(index);
    input_len = strlen(input);
    if (input_len <= index_) {
      return;
    }
    single_char = input[index];
    //...
}
```

This already tells us that input is in fact passed char-by-char through this function!

Then we have 3 cases to consider:

```c
    if ((single_char < '0') || ('9' < single_char)) {
      if (((single_char < 'a') || ('z' < single_char)) &&
         ((single_char < 'A' || ('Z' < single_char)))) {
         // CASE SYMBOLS
        rewritten_symbol = (char *)rewrite_symbols((ulong)(uint)(int)single_char);
        local_30 = (char *)decode_hex(rewritten_symbol);
        input_len = strlen(local_30);
        local_38 = (undefined2 *)malloc(input_len + 3);
        *local_38 = 0x5f;
        strcat((char *)local_38,local_30);
        index_ = 0xffffffffffffffff;
        puVar3 = local_38;
        do {
          if (index_ == 0) break;
          index_ = index_ - 1;
          cVar1 = *(char *)puVar3;
          puVar3 = (undefined2 *)((long)puVar3 + (ulong)bVar4 * -2 + 1);
        } while (cVar1 != '\0');
        *(undefined2 *)((long)local_38 + (~index_ - 1)) = 0x5f;
        strcat(output,(char *)local_38);
        random = rand();
        local_20 = (random - (random >> 0x1f) & 1U) + (random >> 0x1f);
        if (local_20 == 1) {
            // ACTION BASED ON RANDOM
        }
      }
      else {
        // CASE letters
        local_39 = 0;
        local_3a = single_char;
        strcat(output,&local_3a);
      }
    }
    else {
        // CASE numbers
      rewritten_symbol = (char *)number_to_text((ulong)(uint)(int)single_char);
      strcat(output,rewritten_symbol);
      random = rand();
      local_20 = (random - (random >> 0x1f) & 1U) + (random >> 0x1f);
      if (local_20 == 1) {
            // ACTION BASED ON RANDOM
      }
    }
    index = index + 1;
  } while( true );
```

1. Letters are just passed without doing anything to them
2. Symbols are passed via `rewrite_symbols` function. We won't go deep into this, but it basically just replaces symbols with strings like `Double_Quote`. Those strings are stored in the binary as hexencoded strings at `0x00104b88`
3. Numbers are passed via `number_to_text` function. Similarly as above, is replaces digits with textual representation, nothing particularly interesting there.

There is one special thing in this code -> based on `random()` certain action is taken.
Important part of this case code is `strcat(output,key);`
So if the random has certain value the `key` will be pasted in the middle of the encrypted data.
It's easy to see that for `random == 0` this won't happen, so we compile:

```c
int rand(){
    return 0;
}
```

Compile via `gcc -shared -fPIC unrandom.c -o unrandom.so` and run the binary as `LD_PRELOAD=$PWD/unrandom.so ./latte input.txt AAAAAAAAAAAAAAAA output.txt` and therefore we don't worry about the `key` popping up in random places.

#### stage2

We didn't really put much effort in the `stage2` analysis.
There is some complex compression logic, which takes the data generated in `stage1` and merges some character groups into less bytes.
What we're really interested about is just this:

```c
  inputPtr = input;
  outptr = output;
  do {
    if ((*inputPtr == 0) || ((param_2 != 0 && (inputPtr == local_38)))) {
      return outptr + -(long)output;
    }
    local_58 = local_58 & 0xffffffffffff0000 |
               (ulong)(ushort)(short)(char)(&DAT_00104040)[(int)(uint)*inputPtr];
    local_1c = (int)(short)(char)(&DAT_00104040)[(int)(uint)*inputPtr];
    
    // lots of code
     
    *outptr = *inputPtr;
    inputPtr = inputPtr + 1;
    outptr = outptr + 1;
  } while( true );
```

Notice that input is accessed char by char!
It's using `*inputPtr` and at the end of the loop `inputPtr = inputPtr + 1`

## Solution

The idea is pretty clear - we can brute force the flag, or at least the parts that are not compressed:

1. We already noticed before that uppercase letters are passed as-is, so there is not much to be done
2. Symbols and numbers are turned into pretty long texts and then subjected to compression, but most of them are long enough that we can guess which symbol it was before compression. Otherwise we can just encrypt symbols and numbers, and observe the output compressed version. It always looks the same anyway!
3. We don't know where the key was injected, but we can observe bytes which are repeating too much, and assume those come from the key and drop them. Good candidate is `5F 5F BD 61 D7 6A E9 81 E1 36 72 5F`, so we will ignore this.

### Recovering quasi-constant terms of the flag

As said before, we can easily figure out large part of the flag.
See for example prefix:

```
ASIS_Left_B...
```

We should have `ASIS{` and the only symbol text matching `Left_B` is `Left_Brace` anyway.

Now we proceed further, we have uppercase `F` which most likely is just `F`, which we can confirm encrypting `ASIS{F` prefix which matches nicely.

Then we have some `5F 8D 65 5F`, and this we can immediately grab from reference encryptions for symbols and numbers (we create a file with just one symbol and encrypt it).
This comes from `1`.

Then we have `_ag_` and this is just `ag`, which we can immediately grab from reference file where we encrypted every possible 2-byte block.

Finally we have `5F 55 CC 00 73 D6 10 5F` which appears a lot, and this we find in the symbol table as `_`.

Now we already have `ASIS{F1ag_`!

We proceed with this approach for as many characters as we can.
In some places it's tricky, so those we skip for the moment, and recover only obvious parts.
With this we can get up until something like `ASIS{F1ag_C0?_De?3s_Fun_W?_Th3_[f1agz]_?_?3_s?!!}`

### Recovering compressed chunks

We're almost there, now we need to tackle compressed chunks.
The approach here is very similar to what we did before.
It seems the compression works mostly on 2-4 consecutive chars, so we can just generate every possible input and encrypt it.
We consider only lowercase letters, because anything else seems to not be affected by this.
We quickly notice also that some prefixes don't really create any compression, so we can skip those.
If 2-character input does not compress there is no point using it as prefix for compressed blocks.

Now we approach is basically:

1. Locate the first compressed byte to decode.
2. Find every possible input which generates such prefix. In most cases there are maybe 2-3 options.
3. Brute force another 2-character batches for each potential prefix and check with what we need.

For example let's consider end of the flag -> `_s?!!}`
We're missing stuff encoding to `73 DA E8`.
`0x73` is just `s`, so nothing to do here.
Now we're looking for prefixes giving at leats `DA`.
One such prefix is `mile` and it matches exactly what we want.

This takes some time, but we combined with some guessing skills we arrive at:

`ASIS{F1ag_C0mpress_Decompre3s_Fun_With_Th3_{f1agz}_this_tim3_smile!!}`
