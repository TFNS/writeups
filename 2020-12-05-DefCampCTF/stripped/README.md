# Stripped Go (re, 293p, 30 solved)

## Description

```
I heard you can't redo what's deleted. Is that true?

Flag: ctf{sha256(original_message)}
```

In the task we get a [binary](rev_strippedGo_strippedGO.out).

## Task analysis

The difficulty in this task comes from the fact that binary is stripped and we can even easily find `main` here.
Binary itself just outputs some hexencoded data.

Running `strace` and `ltrace` does not give very useful results either.

Via strings we can find some AES-GCM references, but not much more.

### Fixing symbols

If we look for `reversing go` we find:

https://cujo.com/reverse-engineering-go-binaries-with-ghidra/

Apparently it's possible to get back the symbols!
We run the https://github.com/ghidraninja/ghidra_scripts/blob/master/golang_renamer.py script and it all becomes clear.

### Getting the message

Now we know that main is:

```c
void main_main_49B140(void)

{
  ulong *puVar1;
  long in_FS_OFFSET;
  undefined8 local_80;
  undefined local_28 [16];
  undefined local_18 [16];
  
  puVar1 = (ulong *)(*(long *)(in_FS_OFFSET + 0xfffffff8) + 0x10);
  if ((undefined *)*puVar1 <= local_28 && local_28 != (undefined *)*puVar1) {
    fmt_Fprintln_494B80();
    fmt_Fprintln_494B80();
    runtime_stringtoslicebyte_44B700();
    main_EncryptAES_49B340();
    runtime_convTstring_40A160();
    local_28 = CONCAT88(0x4dd760,0x4a69e0);
    local_18 = CONCAT88(local_80,0x4a69e0);
    fmt_Fprintln_494B80();
    return;
  }
  runtime_morestack_noctxt_461740();
  main_main_49B140();
  return;
}
```

So in principal it only really does `main_EncryptAES_49B340`.

We could try to understand which strings are used here (go binary stores them all in one large blob), but we can just put a breakpoint instead.

We break at `0049b340` where `main_EncryptAES` is and we see:

```
 RAX  0x4c0e36 <— 0x6674306e73313067 ('g01sn0tf')
 RBX  0x20
 RCX  0xc000000180 —> 0xc00011e000 —> 0xc00011f000 —> 0xc000120000 —> 0xc000121000 <— ...
 RDX  0x20
*RDI  0xc00011ef18 <— 0x3233736973696874 ('thisis32')
```

If we do `x/2s 0x4c0e36` we get

```
0x4c0e36:       "g01sn0tf0rsk1d1"...
0x4c0e45:       "egc: unswept sp"...
```

So the message we're looking for is `g01sn0tf0rsk1d1e` and flag is: `ctf{a4e394ae892144a54c008a3b480a1b22a6b64dd26c4b0c9eba498330f511b51e}`
