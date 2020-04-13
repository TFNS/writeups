# Baby rust (re, 436p)

In the challenge we get a [rust binary](babyrust) which performs a classic flag-checking.
It's pretty easy to pinpoint the flag-checker function.
We can either look at entry point and then at main:

```c
int main(int argc,char** argv)
{
  code *local_8;
  local_8 = flag_checker;
  FUN_0010e900(&local_8,&PTR_FUN_00134468,(long)argc,argv);
  return;
}
```

Or we can look backwards from the string `nice job` at 0x00128030.
In both cases we end up at 0x001053a0.

There are two important places there.
First one is some constants:

```c
  *constants = 0x6d686461;
  constants[1] = 0x61626070;
  constants[2] = 0x737c4f64;
  constants[3] = 0x754a7d4c;
  constants[4] = 0x6d467676;
  constants[5] = 0x7b697569;
  constants[6] = 0x7d4f4940;
  constants[7] = 0x52565151;
  *(undefined *)(constants + 8) = 0x5a;
```

So we have in memory: `adhmp`badO|sL}JuvvFmiui{@IO}QQVRZ`
Now is we look at where this is used we see those 2 loops (already with some meaningful names):

```c
  FUN_00105720(&user_input,uVar1);
  __ptr = user_input;
  local_68 = local_98;
  local_78 = (undefined4)user_input;
  uStack116 = user_input._4_4_;
  local_70 = (undefined4)local_a0;
  uStack108 = local_a0._4_4_;
  if (local_98 != 0) {
    loop_counter = 0;
    do {
      _loop_counter = (char)loop_counter;
      our_input = *(byte *)((long)user_input + loop_counter);
      if (local_b0 == CONCAT44(uStack180,local_b8)) {
                    /* try { // try from 001054f3 to 001054ff has its CatchHandler @ 00105692 */
        FUN_00105240(&_our_xored_input,local_b0,1);
      }
      loop_counter = loop_counter + 1;
      *(byte *)((long)_our_xored_input + local_b0) = _loop_counter + 7U ^ our_input;
      local_b0 = local_b0 + 1;
    } while (local_98 != loop_counter);
  }
  if (local_48 == local_b0) {
    loop_counter = 0;
    do {
      if (local_b0 == loop_counter) {
        user_input = (undefined **)&DAT_001343f0;
        local_a0 = 1;
        local_98 = 0;
        local_88 = 
        "you fail\nassertion failed: `(left == right)`\n  left: ``,\n right: ``: destination andsource slices have different lengths"
        ;
        local_80 = 0;
        FUN_0010a0d0(&user_input);
        goto LAB_001055b0;
      }
      static_values = (char *)((long)constants + loop_counter);
      our_xored_input = (char *)((long)_our_xored_input + loop_counter);
      loop_counter = loop_counter + 1;
    } while (*static_values == *our_xored_input);
  }
```

The second loop actually touches the `constants` array we have seen, and compares it with some buffer. 
If we backtrack to see where this comparison buffer comes from we can see that it's created by `_loop_counter + 7U ^ our_input`.

This basically means that we need to provide such input, that once it's transformed via `_loop_counter + 7U ^ our_input` it will be equal to the constant buffer.
Of course we can use XOR and subtraction in place of XOR and addition, and simply decrypt the constant buffer:

```python
def main():
    data = '61 64 68 6d 70 60 62 61 64 4f 7c 73 4c 7d 4a 75 76 76 46 6d 69 75 69 7b 40 49 4f 7d 51 51 56 52 5A'.replace(" ", '').decode("hex")
    print(data)
    print("".join([chr(i + 7 ^ ord(x)) for i, x in enumerate(data)]))

main()
```

And we get: `flag{look_ma_i_can_write_in_rust}`
