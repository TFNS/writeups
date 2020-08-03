# ArchRide (re, 456p, 36 solved)

## Description

We get a bzip2 archive with a [surprise](surprise).
The archive contains ELF binary.
There is a hint:

```
There may be multiple solutions per level. 
Limit your solutions to valid base64 (a-zA-Z0-9/+). 
You can check for corruption to find the correct input for a level!
```

## Analysis

The binary is pretty simple:

```c
undefined8 main(void)

{
  int xors_passed;
  size_t input_len;
  char acStack27 [15];
  int i;
  
  printf("Enter Key:");
  i = 0;
  while (i < 0xe) {
    *(undefined4 *)(&buffer_with_user_input + (long)i * 4) = 0;
    i = i + 1;
  }
  fgets(acStack27,0xf,stdin);
  fill_buffer_with_user_data(acStack27);
  xors_passed = xor_checks(acStack27);
  if (((xors_passed == 1) && (xors_passed = xor_checks2(acStack27), xors_passed == 1)) &&
     (input_len = strlen(acStack27), input_len == 0xe)) {
    drop_new_binary();
    puts("Surprise!");
    return 0;
  }
  puts("Need a better key :(");
  return 0;
}
```

There are 2 functions with some xor checks on the input parameters, looks rather Z3-able.
Once you pass the checks, the binary executes:

```c

void drop_new_binary(void)

{
  FILE *__s;
  void *__ptr;
  int index;
  
  __s = fopen("surprise","wb");
  __ptr = malloc(0xffef1);
  if (__s != (FILE *)0x0) {
    index = 0;
    while (index < 0xffef2) {
      *(byte *)((long)__ptr + (long)index) =
           (byte)(&enc_new_binary)[index] ^
           (byte)*(undefined4 *)(&buffer_with_user_input + (long)(index % 0xd) * 4);
      index = index + 1;
    }
    fwrite(__ptr,0xffef1,1,__s);
    fclose(__s);
    free(__ptr);
  }
  return;
}
```

This basically XORs the `key % 0xd` with some constant array in memory, and saves this in place of `surprise` file.
And this file is again a bzip2 archive with a binary, which looks very similar, just the xor checks (and so key) are different, and so is the architecture of the binary!

## Solution

The idea seems pretty clear -> we need to:

- Recover the key
- Drop new binary

and repeat this many many times to get the flag.

First part seems reasonably simple -> we could use Z3 or just angr to solve this.
It somewhat works, but it turns out for some architectures angr fails :(

Second part seems simple at first, but then you arrive at stuff like ARM or PPC and it's not longer that easy to just run the binary and pass the right key, because you'd need something like qemu to run all of this...

### "Proper" angr solver

Let's start off with the proper angr solver, since it's going to be needed at the very last stage, and it was also useful to get started.

The only hard part was to set the target/avoid because waiting for stdout messages was very slow, and for PIE binary it's not easy to pinpoint the right addresses.
We use the stdout as fallback, but for the real targets we pass `fopen` and `puts`.
This follows the idea that binary calls `fopen` when key is correct and it drops new archive, and it calls `puts` to print the failure message:

```python
def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b"Surprise" in stdout_output


def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b"Need a better" in stdout_output

def solve_key():
    p = angr.Project(main_dir + 'surprise.out', load_options={'auto_load_libs': False})
    GOOD = is_successful
    BAD = should_abort
    try:
        cfg = p.analyses.CFGFast()
    except:
        pass
    for _, funcInfo in p.kb.functions.items():
        if 'fopen' in funcInfo.name:
            GOOD = funcInfo.addr
        elif 'puts' in funcInfo.name:
            BAD = funcInfo.addr

    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(0xe)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
    st = p.factory.blank_state(stdin=flag, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})

    for k in flag_chars:
        st.solver.add(k < 123)
        st.solver.add(k > 42)
        for x in range(44, 47):
            st.solver.add(k != x)
        for x in range(58, 65):
            st.solver.add(k != x)
        for x in range(91, 97):
            st.solver.add(k != x)
    simulation = p.factory.simgr(st)
    x = simulation.explore(find=GOOD, avoid=BAD)
    for found in simulation.found:
        res = []
        for arg in flag_chars:
            res.append(found.solver.eval(arg, cast_to=int))
        print(res)
        result = "".join(map(chr, res))
        print(result)
        return result
```

This works pretty well for first few levels.
It has some issues with one of the levels where variables were not well constrained and there were many potential keys, most of them wrong.
It eventually fails miserably at PPC architecture :(

### Smart solution

One problem here was angr not being able to solve some architectures (possibly this could be mitigated) but another issue was of course running the binary to get new archive.
We decided it might be much easier to decrypt and drop the archive `by hand` instead.

#### Reading encrypted payload

First we need to extract the payload.
Fortunately it's not that difficult to pinpoint -> it ends where constant string `GCC:` is located in memory.
Then it follows a very clear pattern -> it's encoded as 8 byte values with only 1 active byte.
So we can move upwards as long as we see this pattern of 8 bytes with just one active.
Finally in some cases we had to drop the zero at the start.
We don't know if the current binary is little or big endian but we can just look at the first value we recovered and we see if first or last bytes are active:

```python
def read_archive_data():
    with open(main_dir + "surprise.out", 'rb') as f:
        data = f.read()
    current = data.index(b"GCC: ")
    endian = 'little'
    if int.from_bytes(data[current - 8:current], 'little') > 256:
        endian = 'big'
    vals = []
    while True:
        v = int.from_bytes(data[current - 8:current], endian)
        if v < 256:
            vals.append(v)
        else:
            break
        current -= 8
    vals = vals[::-1]
    if vals[0] == 0:
        vals = vals[1:]
    return vals
```

#### Recovering the key 

Now we want to recover the key without using angr or any other smart tools.
This turns out to be actually trivial if we spent 1 minute to look at those bzip2 archives we already dropped.
Specially look at the headers:

```
42 5A 68 39 31 41 59 26 53 59 52 C8 3A B0 06 47 
F3 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
FF FF FF E1 8E 33 6E F7 73 A1 D7 AC F7 96 F7 97
```

```
42 5A 68 39 31 41 59 26 53 59 39 AC 24 61 06 49 
1E FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
FF FF FF E1 8D 7F 5F 7B EE BE BA BB B6 3D BB B7
```

```
42 5A 68 39 31 41 59 26 53 59 DF C1 29 3A 06 49 
A9 7F FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
FF FF FF E1 8D 5F 7D 8E FB EF 5E F7 9E F7 8F 57
```

Not only the first 10 bytes are identical, since it's bzip2 header -> `42 5A 68 39 31 41 59 26 53 59` but more importantly what is with all those `FF`?!

Note that key is 14 bytes and they use only 13 to decrypt payload, and here we have 10 bytes of contant header and about 30 `FF` bytes.
More than enough to recover the key:

```python
def solve_key2(data):
    print([hex(c) for c in data[:10]])
    known_key1 = [a ^ b for a, b in zip(b'\xff' * 33, data[0x13:])]
    print(known_key1)
    expected_header = b'\x42\x5A\x68\x39\x31\x41\x59\x26\x53\x59'
    known_key3 = [a ^ b for a, b in zip(expected_header, data)]
    print(known_key3)
    key = (known_key3 + known_key1[4:])[:14]
    print(key)
    key = "".join(map(chr, key))
    print(key)
    return key
```

### Plugging in

We now can run this in a loop:

```python
def main():
    index = 0
    while True:
        data = read_archive_data()
        result = solve_key(data)
        decode_new_archive(data, index, result)
        # unpack and prepare next stage
        time.sleep(5)
        os.system('bzip2 -d -f -k ' + main_dir + 'surprise_' + str(index))
        time.sleep(5)
        if os.path.exists(main_dir + 'surprise_' + str(index) + '.out'):
            os.system('cp ' + main_dir + 'surprise_' + str(index) + '.out ' + main_dir + 'surprise.out')
            index += 1
        break
```

And it works like a charm until the very last stage, where we get some broken key and the dropped file is not a valid archive anymore.
Fortunately we still have the angr solver, so we just run it with the last binary, and we get a nice key.
It turns out the last binary drops ELF instead of bzip2, and flag is in strings: `inctf{x32_x64_ARM_MAC_powerPC_4rch_maz3_6745}`
