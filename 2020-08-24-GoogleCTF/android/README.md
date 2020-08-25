# Android (re, 94p, 131 solved)

## Description

In the task we get [an app](reverse.apk) to reverse.
Once launched the app asks us for a flag, and then validates it for us.
Unlike in many android challenges, there are no native libraries included, so we're working with pure JVM/Dalvik code.

## Static analysis

### Decompilation

Static analysis seems to be a bit tricky, because all general decompilation tools (like ByteCodeViewer or more directly dex2jar) fail on the key classes.

One class `R` that we can decompile has just one recursive function:

```java
public static long[] ő(final long n, final long n2) {
    if (n == 0L) {
        return new long[] { 0L, 1L };
    }
    final long[] result = ő(n2 % n, n);
    return new long[] { result[1] - n2 / n * result[0], result[0] };
}
```

Remaining 2 key classes -> main Activity and some OnClickListener are causing issues to dex2jar.

### Reversing Smali

While we can't decompile those classes or even create a standard JVM bytecode, we must be able to dump Smali Dalvik bytecode, since this is what is actually executed.
We can do that with `baksmali` tool.

From this we get [activity](activity.smali) and [listener](listener.smali) (renamed to simplicity).

#### Main activity

We start by looking at the smaller file - activity.
There are 3 fields in this class:

```
# instance fields
.field class:[J

.field ő:I

.field ő:[J
```

`Long array` called `class`, `Long array` called `ő` and `Integer` called `ő`

First array is assigned from:

```
    const/16 v0, 0xc

    new-array v1, v0, [J

    fill-array-data v1, :array_18

    iput-object v1, p0, Lcom/google/ctf/sandbox/ő;->class:[J
```

`0xc` is the size of the array, then it's loaded with constant labelled `array_18`, and finally this is assigned to `Long array` called `class`.

The constant initializer is:

```
    :array_18
    .array-data 8
        0x271986b
        0xa64239c9L
        0x271ded4b
        0x1186143
        0xc0fa229fL
        0x690e10bf
        0x28dca257
        0x16c699d1
        0x55a56ffd
        0x7eb870a1
        0xc5c9799fL
        0x2f838e65
    .end array-data
```

Second array is assigned from:

```
    new-array v0, v0, [J

    iput-object v0, p0, Lcom/google/ctf/sandbox/ő;->ő:[J
```

So it's also `0xc` in size, but it's empty.

Finally the integer is assigned from:

```
    const/4 v0, 0x0

    iput v0, p0, Lcom/google/ctf/sandbox/ő;->ő:I
```

So it's initalized with 0.

Rest of this class is irrelevant for us.
It basically creates a listener for the button on the screen, and that's about it.

#### Listener

The real flag checking logic is hidden in the listener in `onClick` method.
It might look at bit scary, because it's long, however most of it is just a red herring...

##### Red herring

The code starts by a very long repeating code like:

```
    new-array v2, v2, [Ljava/lang/Object;

    const/16 v8, 0x41

    .line 45
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    aput-object v8, v2, v3

    const/16 v8, 0x70

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    aput-object v9, v2, v6

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    aput-object v8, v2, v5
```

There is nothing particularly interesting about this code, we're only interested in:

```
const/16 v8, 0x70
```
and
```
invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;
```

It loads value to a register and then calls `valueOf` to create Integer object.
Later in the code it takes those ints and uses StringBuilder to construct a string out of them.
The string is: `Apparently this is not the flag. What's going on?` and is just a red herring...

##### Actual flag checking

What we're really interested in starts at `.line 61` marker.

```
    .line 61
    .local v3, "flagString":Ljava/lang/String;
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v5

    const/16 v6, 0x30

    if-eq v5, v6, :cond_21f

    .line 62
    iget-object v4, v1, Lcom/google/ctf/sandbox/ő$1;->val$textView:Landroid/widget/TextView;

    const-string v5, "\u274c"

    invoke-virtual {v4, v5}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 63
    return-void
```

They take length of our input flag string and compare it against `0x30`.
If it's matching we go to `cond_21f`, otherwise we get `\u274c` printed (red X) and function returns, so we failed.

If we got the size right we get to:

```
    .line 65
    :cond_21f
    const/4 v5, 0x0

    .line 65
    .local v5, "i":I
    :goto_220
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v6

    div-int/2addr v6, v7

    if-ge v5, v6, :cond_272
```

This is a loop `for(int i=0;i<flagString.length()/4;i++)` with `i` at `v5`
Then inside this loop we have 4 very similar blocks:

```
    .line 66
    iget-object v6, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v6, v6, Lcom/google/ctf/sandbox/ő;->ő:[J

    mul-int/lit8 v8, v5, 0x4

    add-int/2addr v8, v4

    invoke-virtual {v3, v8}, Ljava/lang/String;->charAt(I)C

    move-result v8

    shl-int/lit8 v8, v8, 0x18

    int-to-long v8, v8

    aput-wide v8, v6, v5
```

1. Load reference to the empty array we have in `activity` class to `v6` register
2. Multiply `i` loop counter by `4` and add `v4` (which is constant `3`), and store to `v8`
3. Use this value as index in the array with our input flag
4. Take value at this index, shift by 0x18, convert result to long and put in the empty array we have.

Otherwise:

```python
v8 = i * 4 + 3
v8 = flag_string[v8]
v8 = v8 << 0x18
v6[i] = v8
```

We could go through the next 3 blocks the same way, but they do pretty much the same, with some small const changes.
At the very end of the loop we have:

```
    .line 65
    add-int/lit8 v5, v5, 0x1
```

so as expected, loop couter `i` is bumped by 1 each iteration.
    
Python version of those 4 similar blocks is:

```python
def fill_array(flag_string):
    v6 = [None for _ in range(0xc)]
    for i in range(len(flag_string) / 4):
        v8 = i * 4 + 3
        v8 = flag_string[v8]
        v8 = v8 << 0x18

        v10 = i * 4 + 2
        v10 = flag_string[v10]
        v10 = v10 << 0x10
        v8 = v8 | v10

        v10 = i * 4 + 1
        v10 = flag_string[v10]
        v10 = v10 << 0x8
        v8 = v8 | v10

        v10 = i * 4
        v10 = flag_string[v10]
        v8 = v8 | v10
        v6[i] = v8
    return v6
```

It's not difficult to recognize that this is in fact simply conversion of a character string into array of 4-byte integer values, big endian.

Going further:

```
    const-wide v4, 0x100000000L

    .line 73
    .local v4, "m":J
```

Long variable `m` is loaded with constant `0x100000000L`

```
    iget-object v6, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v7, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v7, v7, Lcom/google/ctf/sandbox/ő;->ő:[J

    iget-object v8, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget v8, v8, Lcom/google/ctf/sandbox/ő;->ő:I

    aget-wide v8, v7, v8

    invoke-static {v8, v9, v4, v5}, Lcom/google/ctf/sandbox/R;->ő(JJ)[J

    move-result-object v6

    .line 74
    .local v6, "g":[J
```

Here we finally see a call to the function we managed to decompile initially!
We take value from those big endian longs we generated, at index pointed by the integer class field in `activity`, and invoke the function as `g = R_fun(array[idx], m)`.

Then we have:

```
    const/4 v7, 0x0

    aget-wide v7, v6, v7

    rem-long/2addr v7, v4

    add-long/2addr v7, v4

    rem-long/2addr v7, v4

    .line 75
    .local v7, "inv":J
```

And this translates to `inv = g[0] % m` using registers loaded before.
Then we have:

```
    iget-object v9, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v9, v9, Lcom/google/ctf/sandbox/ő;->class:[J

    iget-object v10, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget v10, v10, Lcom/google/ctf/sandbox/ő;->ő:I

    aget-wide v10, v9, v10

    cmp-long v9, v7, v10

    if-eqz v9, :cond_2a3
```

Here note that we use `Lcom/google/ctf/sandbox/ő;->class:[J` so the array loaded with static values in `activity` class!
What we do, is we check `static_array[idx] == inv`

Then we either go to failure branch or do:

```
    .line 79
    :cond_2a3
    iget-object v9, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget v10, v9, Lcom/google/ctf/sandbox/ő;->ő:I

    const/4 v11, 0x1

    add-int/2addr v10, v11

    iput v10, v9, Lcom/google/ctf/sandbox/ő;->ő:I
```

So pretty much just increment the integer field in `activity` by 1.
And finally:

```
    .line 81
    iget-object v9, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget v9, v9, Lcom/google/ctf/sandbox/ő;->ő:I

    iget-object v10, v1, Lcom/google/ctf/sandbox/ő$1;->this$0:Lcom/google/ctf/sandbox/ő;

    iget-object v10, v10, Lcom/google/ctf/sandbox/ő;->ő:[J

    array-length v10, v10

    if-lt v9, v10, :cond_2be
```

So once this integer matches length of the array, we finish.

So this whole part is simply doing something like:

```python
for idx in range(len(array)):
    m = 0x100000000
    g = R(array[idx], m)
    inv = g[0] % m
    assert (static_array[idx] == inv)
```

##### Pythonized code:

Finally the flag checker basically does:

```python
flag = 'CTF{something here....}'
static_array = [0x271986b, 0xa64239c9, 0x271ded4b, 0x1186143, 0xc0fa229f, 0x690e10bf, 0x28dca257, 0x16c699d1, 0x55a56ffd, 0x7eb870a1, 0xc5c9799f,0x2f838e65]
array = [bytes_to_long_be(c) for c in chunk(flag, 4)]
for idx in range(len(array)):
    m = 0x100000000
    g = R_fun(array[idx], m)
    inv = g[0] % m
    assert (static_array[idx] == inv)
```

## Solver

Now the question is how do we solve this!
We could try to invert the `R_fun`, but we're too lazy for that.
The checker works chunk by chunk, and each chunk is just 4 bytes long.
We can easily brute-force all possible printable values of such chunk, and simply test which one produces matching block...

```python
def worker(data):
    a, static_index = data
    static_array = [0x271986b, 0xa64239c9, 0x271ded4b, 0x1186143, 0xc0fa229f, 0x690e10bf, 0x28dca257, 0x16c699d1, 0x55a56ffd, 0x7eb870a1, 0xc5c9799f,
                    0x2f838e65]
    for b in string.printable:
        for c in string.printable:
            for d in string.printable:
                potential = a + b + c + d
                val = bytes_to_long_be(potential)
                if compare_b(val, static_array[static_index]):
                    print('found', a + b + c + d)
                    return a + b + c + d


def main_d():
    charset = '_' + string.printable
    data = [(c, 0) for c in charset]
    brute(worker, data, processes=6)


if __name__ == '__main__':
    freeze_support()
    main_d()
```

We need to run this 12 times, each time changing the block index in data.
We can kill the processes once we hit "found" message.
It takes a moment and we recover: `CTF{y0u_c4n_k3ep_y0u?_m4gic_1_h4Ue_laser_b3ams!}`
