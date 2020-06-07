# MoM's touch (re, 167p, 98 solved)

A classic RE challenge.
We get ELF [binary](momsTouch) to reverse.

## Analysis

The main is just:

```c
int main(void)

{
  ssize_t inputLen;
  size_t inputStrlen;
  undefined4 check;
  char *msg;
  char *inputBuffer;
  
  FUN_080486b0();
  puts("Mom Give Me The FLAG!");
  inputBuffer = (char *)malloc(100);
  if (inputBuffer == (char *)0x0) {
    inputBuffer = "[*]Error : malloc()";
  }
  else {
    inputLen = read(0,inputBuffer,100);
    if (-1 < inputLen) {
      if (inputBuffer[inputLen + -1] == '\n') {
        inputBuffer[inputLen + -1] = '\0';
      }
      inputStrlen = strlen(inputBuffer);
      if (inputStrlen == 0x49) {
        check = flag_check(inputBuffer);
        if ((char)check == '\0') {
          msg = "Try Again..";
        }
        else {
          msg = "Correct! Mom! Input is FLAG!";
        }
        puts(msg);
        free(inputBuffer);
        return 0;
      }
      puts("Mom, Check the legnth..");
      exit(0);
    }
    inputBuffer = "[*]Error : read()";
  }
  perror(inputBuffer);
  exit(-1);
}
```

There are 2 checks, first one is `inputStrlen == 0x49` so we know the flag length is `0x49` bytes long.

Now the real flag checker:

```c
int flag_check(char *input)

{
  uint some_const;
  int random;
  uint random2;
  int index;
  
  index = 0;
  do {
    some_const = random_generated_consts[index];
    random = rand();
    random2 = random + ((random / 0xff + (random >> 0x1f)) -
                       (int)((longlong)random * 0x80808081 >> 0x3f)) * -0xff;
    if (((int)input[index] ^ random_generated_consts[(some_const >> 4 | some_const << 4) & 0xff] ^
        random_generated_consts[(random2 >> 2 | random2 * 4) & 0xff]) != target[index]) {
      return 0;
    }
    index = index + 1;
  } while (index < 0x49);
  return 1;
}
```

It seems strange, because this code is using some memory at `080492ac` which we haven't seen yet, and also utilizes `rand()` function!
We can look at this memory and follow where it's written - turns out it's in `_INIT_1`.
This function also contains `srand(0xff)`.
It explains how the binary uses `rand()` and yet the results are somehow reproducible (after all the flag has to be always the same).

## Solution

Now we could try to reverse the generation of this `random_generated_consts` and then figure out the values which are XORed with our input and compared against a static buffer at `08049144` but there is an easier way.

We can put a breakpoint in the code, where the XOR happens.
Then either dump the XOR keystream, or simply brute-force the input values to match the target.
We chose the second one, because it was simpler to write:

1. Put breakpoint at `0x8048812` where the final cmp instruction is located
2. Create file with input for the flag (possible also with `r <<< $(python -c "print...")` but can have issues with weird characters).
3. Run the binary with given inputs `r < input.txt`
4. Now execute continue as many times as we already know characters in the flag (since it will trigger the breakpoint every time)
5. Finally we do one last continue, and now there are 2 outcomes:
   - if our character was valid, we will hit another breakpoint
   - if our character was invalid, we will immediately return with 0 and binary will exit

```python
import gdb
import codecs
import string
gdb.execute("break *0x8048812") # cmp
flag = "Defenit{"
for i in range(0x49-len(flag)):
    for c in string.printable:
        potential_flag = flag+c
        with codecs.open("input.txt","w") as output_file:
            padding = 0x49-len(potential_flag)
            output_file.write(potential_flag+('a'*padding))
        try:
            gdb.execute("r < input.txt")
            for j in range(len(potential_flag)): # skip known chars
                gdb.execute("continue")
            gdb.execute("continue")
            print("hit breakpoint!")
            #good character
            flag = potential_flag
            print("current flag", flag)
            break
        except: # program exited without hitting any breakpoints
            continue
print(flag)
```

This approach will fail for the very last flag character, but we don't care, we know it's `}`.

We can run this with `gdb ./momsTouch -x solver.py` and after a moment we get back:

`Defenit{ea40d42bfaf7d1f599abf284a35c535c607ccadbff38f7c39d6d57e238c4425e}`
