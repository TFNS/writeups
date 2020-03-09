# Easy strcmp (re, 265p, ? solved)

A classic password-checker RE problem.
We get [a binary](easystrcmp) which checks flag for us.

The twist is that what we see is:

```c
undefined8 main(int argc,undefined8 *argv)

{
  int iVar1;
  
  if (argc < 2) {
    printf("Usage: %s <FLAG>\n",*argv);
  }
  else {
    iVar1 = strcmp((char *)argv[1],"zer0pts{********CENSORED********}");
    if (iVar1 == 0) {
      puts("Correct!");
    }
    else {
      puts("Wrong!");
    }
  }
  return 0;
}
```

And for the flag `zer0pts{********CENSORED********}` the binary responds `Wrong!` so there is something more here.

Once we step through this code with a debugger it turns out this strcmp call takes us to some different place, specifically to `0x001006ea`.

This function is:

```c
void weird_function(long our_input,undefined8 censored_flag)

{
  int input_len;
  int i;
  
  // strlen
  input_len = 0;
  while (*(char *)(our_input + input_len) != '\0') {
    input_len = input_len + 1;
  }
  
  // "decryptin" our input flag
  i = 0;
  while (i < (input_len >> 3) + 1) {
    *(long *)(our_input + (i << 3)) =
         *(long *)(our_input + (i << 3)) - *(long *)(&const_array + (long)i * 8);
    i = i + 1;
  }
  
  // real strcmp call
  (*DAT_00301090)(our_input,censored_flag,our_input,censored_flag);
  return;
}
```

What happens is that our input if first passed through this code, and only at the very end it calls the real `strcmp` comparing our modified input with `zer0pts{********CENSORED********}`.

We can see that this encoding/encryption process is quite simple, is just subtracts values from a constant array.
We managed to invert this by:

```python
v = [0x42, 0x09, 0x4a, 0x49, 0x35, 0x43, 0x0a, 0x41, 0xf0, 0x19, 0xe6, 0x0b, 0xf5, 0xf2, 0x0e, 0x0b, 0x2b, 0x28, 0x35, 0x4a, 0x06, 0x3a, 0x0a, 0x4f]
res = ''
pattern = '********CENSORED********'
for i in range(len(v)):
    if i in (9, 11, 13, 14):
        res += (chr((ord(pattern[i]) + v[i] + 1) % 256))
    else:
        res += (chr((ord(pattern[i]) + v[i]) % 256))
print("zer0pts{" + res + "}")
```

And we recover `zer0pts{l3ts_m4k3_4_DETOUR_t0d4y}`.

Notice that for bytes 9, 11, 13 and 14 for some reason there was off-by-one, but it was easy to spot, because we simply put breakpoint on the line with real `strcmp` call and checked how our inputs were encoded, and we could see that instead of `CENSORED` some of the letters were shifted by 1.
