# wysinwyg (re, 537p, ? solved)

We get yet another password checking [binary](wysinwyg).
Another challenge where, similarly to `easy strcmp`, the binary seems to do something else than what it seems.

The main claims to be:

```c
undefined8 main(int argc,long argv)
{
  if (argc == 2) {
    puts(*(char **)(argv + 8));
  }
  else {
    puts("Feed me flag");
  }
  return 0;
}
```

But in reality we also get a message `Wrong!` when we input the flag!

It all comes down to what happens before main is called from the entry point.
`__libc_start_main` apart from pointer to `main` gets also some arrays with init functions.

In our case interesting one is `_INIT_1` which is doing some crazy stuff.
The important part is:

```c
    do {
      syscall(0x65,0x18,(ulong)local_17c,0,0);
      syscall(0x3d,(ulong)local_17c,&local_180,0,local_178);
      if (((local_180 & 0xff) == 0x7f) && ((local_180 & 0x8000) != 0)) {
        syscall(0x65,0xc,(ulong)local_17c,0,local_e8);
        flag_checker((ulong)local_17c,local_e8,local_e8);
      }
      if ((local_180 & 0x7f) == 0) {
        syscall(0xe7,0);
      }
    } while( true );
```

It seems to spawn a monitoring process of some sort and in a loop it calls function at `0x001007e1`.

This function is:

```c

void flag_checker(uint param_1,long param_2)

{
  ulong uVar1;
  int iVar2;
  long flag_input;
  
  uVar1 = *(ulong *)(param_2 + 0x78);
  if (uVar1 == 5) {
    checking_status = 0;
  }
  else {
    if (uVar1 < 6) {
      if (uVar1 == 1) {
        flag_input = ptrace(PTRACE_PEEKDATA,(ulong)param_1,*(undefined8 *)(param_2 + 0x68),0);
        *(undefined8 *)(param_2 + 0x60) = 1;
        iVar2 = weird_fun((long)(char)flag_input,0x5beb,0x8bae6fa3);
        checking_status =
             checking_status |
             iVar2 - (int)*(undefined8 *)(&const_array + (long)(int)byte_counter * 8);
        // 0.5*8 so just shift by 4 bytes
        byte_counter = byte_counter + 0.50000000;
      }
    }
    else {
      if (uVar1 == 0xc) {
        byte_counter = 0.00000000;
      }
      else {
        if (uVar1 == 0xe7) {
          if (checking_status == 0) {
            puts("Correct!");
          }
          else {
            puts("Wrong!");
          }
        }
      }
    }
  }
  syscall(0x65,0xd,(ulong)param_1,0,param_2);
  return;
}
```

Not exactly sure of the internal works, but it seems that:

```c
flag_input = ptrace(PTRACE_PEEKDATA,(ulong)param_1,*(undefined8 *)(param_2 + 0x68),0)
```

returns a single flag character.
Then this function calls some strange recursive function at `0x0010075a`.
Then some const is subtracted from the results, and the final value ORed to the checking status:

```c
iVar2 = weird_fun((long)(char)flag_input,0x5beb,0x8bae6fa3);
checking_status =
     checking_status |
     iVar2 - (int)*(undefined8 *)(&const_array + (long)(int)byte_counter * 8);
byte_counter = byte_counter + 0.50000000;
```

Since we expect the `checking_status` to be `0` then it's safe to assume that we want the weird function to return exactly the same value as the `4 byte` values in the constant array.

The weird function is:

```c
long weird_fun(long flag_input,long val_1,long val_2)

{
  long lVar1;
  
  if (flag_input == 0) {
    val_2 = 0;
  }
  else {
    if (val_1 == 0) {
      val_2 = 1;
    }
    else {
      lVar1 = weird_fun(flag_input,val_1 + -1,val_2,val_1 + -1);
      val_2 = (val_2 + ((lVar1 * (flag_input % val_2)) % val_2) % val_2) % val_2;
    }
  }
  return val_2;
}
```

Which written in python is:

```python

def weird_fun(flag_input, val_1, val_2):
    if val_1 == 0:
        val_2 = 1
    else:
        lVar1 = weird_fun(flag_input, val_1 - 1, val_2)
        val_2 = (val_2 + ((lVar1 * (flag_input % val_2)) % val_2) % val_2) % val_2
    return val_2
```

And in faster non-recursive version:

```python
def weird_fun2(flag_input, val_1, val_2_orig):
    val_2 = 1
    for i in range(val_1):
        lVar1 = val_2
        val_2 = (val_2_orig + ((lVar1 * (flag_input % val_2_orig)) % val_2_orig) % val_2_orig) % val_2_orig
    return val_2
```

Now we can just grab the constants from the memory, and check which one of the corresponds to which character.
Since the function does not care about the position of the flag character, we can calculate all possible resuls for whole flag charset, make a map, and then decode the memory constants:

```python
from crypto_commons.generic import bytes_to_long

def weird_fun2(flag_input, val_1, val_2_orig):
    val_2 = 1
    for i in range(val_1):
        lVar1 = val_2
        val_2 = (val_2_orig + ((lVar1 * (flag_input % val_2_orig)) % val_2_orig) % val_2_orig) % val_2_orig
    return val_2


def main():
    bytes = [0x38, 0x01, 0x40, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x67, 0xB8, 0x9A, 0x27, 0x00, 0x00, 0x00, 0x00, 0x69, 0x29, 0x7D, 0x17, 0x00, 0x00, 0x00, 0x00,
             0xF5, 0x46, 0x6E, 0x0E, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x21, 0x26, 0x51, 0x00, 0x00, 0x00, 0x00, 0x73, 0xCE, 0x96, 0x2E, 0x00, 0x00, 0x00, 0x00,
             0x96, 0xB4, 0x84, 0x04, 0x00, 0x00, 0x00, 0x00, 0x6E, 0x4F, 0x41, 0x73, 0x00, 0x00, 0x00, 0x00, 0x96, 0xB4, 0x84, 0x04, 0x00, 0x00, 0x00, 0x00,
             0xE9, 0x74, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x96, 0xB4, 0x84, 0x04, 0x00, 0x00, 0x00, 0x00, 0x62, 0xC7, 0x7D, 0x63, 0x00, 0x00, 0x00, 0x00,
             0x4A, 0x7A, 0x14, 0x15, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x89, 0xE9, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x89, 0xE9, 0x1F, 0x00, 0x00, 0x00, 0x00,
             0xEB, 0x01, 0x2B, 0x86, 0x00, 0x00, 0x00, 0x00, 0xCD, 0x06, 0x5A, 0x77, 0x00, 0x00, 0x00, 0x00, 0xF5, 0x46, 0x6E, 0x0E, 0x00, 0x00, 0x00, 0x00,
             0xF5, 0x46, 0x6E, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x66, 0x24, 0x6A, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x6D, 0xAB, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
             0x12, 0xCC, 0x67, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7E, 0x16, 0x34, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x01, 0x2B, 0x86, 0x00, 0x00, 0x00, 0x00,
             0x6D, 0xAB, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x96, 0xB4, 0x84, 0x04, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x01, 0x2B, 0x86, 0x00, 0x00, 0x00, 0x00,
             0x6D, 0xAB, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x4D, 0xDA, 0xEF, 0x11, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x21, 0x26, 0x51, 0x00, 0x00, 0x00, 0x00,
             0xF5, 0x46, 0x6E, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x69, 0x29, 0x7D, 0x17, 0x00, 0x00, 0x00, 0x00, 0x73, 0xCE, 0x96, 0x2E, 0x00, 0x00, 0x00, 0x00,
             0x4A, 0x7A, 0x14, 0x15, 0x00, 0x00, 0x00, 0x00, 0x12, 0xCC, 0x67, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x73, 0xCE, 0x96, 0x2E, 0x00, 0x00, 0x00, 0x00,
             0x4D, 0x14, 0x80, 0x78, 0x00, 0x00, 0x00, 0x00, 0x6B, 0xED, 0x69, 0x5A, 0x00, 0x00, 0x00, 0x00]

    mapped_function_results = {}
    for c in range(32, 128):
        result = weird_fun2(c, 0x5beb, 0x8bae6fa3)
        mapped_function_results[result] = chr(c)
    flag = ''
    for fbte in range(len(bytes) / 8 - 1):
        expected = bytes_to_long("".join(map(chr, bytes[fbte * 8: (fbte + 1) * 8][::-1])))
        flag += mapped_function_results[expected]
    print(flag)

main()
```

And from that we get: `zer0pts{sysc4ll_h00k1ng_1s_1mp0rt4nt}`
