# QR Puzzle (re, 314p, ? solved)

In the challenge we get [encryption binary](chall), [encrypted qr code](encrypted.qr) and [key](key).

The goal is to decrypt the qr code to get the flag.

We started off by doing some blackbox analysis of the binary, and we quickly noticed that each entry in the `key` files corresponds to a single `swap` between some adjacent cells in the matrix.

It's easy to spot if you have only a single key entry, then two etc.

It also became apparent that one of the positions which are swapped is defined by coordinates in parenthesis, and the other one is adjacent, with the location defined by the first number in the key entry.

Finally we loaded the binary into ghidra to confirm our findings.
The key function with named variables is:

```c
void encrypt(long qr,int *key)

{
  long *plVar1;
  long *plVar2;
  int adjacent_selector;
  int row;
  long column;
  int adjacent_column;
  long lVar3;
  int adjacent_row;
  
  // select adjacent cell to swap with 
  do {
    if (key == (int *)0x0) {
      return;
    }
    adjacent_selector = key[2];
    adjacent_column = *key;
    column = (long)adjacent_column;
    row = key[1];
    adjacent_row = row;
    if (adjacent_selector == 1) {
      adjacent_column = adjacent_column + 1;
    }
    else {
      if (adjacent_selector < 2) {
        if (adjacent_selector == 0) {
          adjacent_column = adjacent_column + -1;
        }
        else {
LAB_00400c70:
          adjacent_row = row;
        }
      }
      else {
        if (adjacent_selector == 2) {
          adjacent_row = row + -1;
        }
        else {
          adjacent_row = row + 1;
          if (adjacent_selector != 3) goto LAB_00400c70;
        }
      }
    }
    // swap values
    plVar1 = (long *)(qr + (long)row * 8);
    lVar3 = (long)adjacent_column;
    plVar2 = (long *)(qr + (long)adjacent_row * 8);
    *(char *)(*plVar1 + column) = *(char *)(*plVar1 + column) + *(char *)(*plVar2 + lVar3);
    *(char *)(*plVar2 + lVar3) = *(char *)(*plVar1 + column) - *(char *)(*plVar2 + lVar3);
    *(char *)(column + *plVar1) = *(char *)(column + *plVar1) - *(char *)(*plVar2 + lVar3);
    key = *(int **)(key + 4);
  } while( true );
}
```

The first part of the code selects the adjacent cell to perform swap with.
We can see that based on the first value in key entry we either to +1 or -1 on either row(2,3) or column (0,1).

The swap looks scary but it simply does:

```
x = A
y = B
//
x = x+y // x = A+B
y = x-y // y = A+B-B = A
x = x-y // x = A+B-A = B 
```

We could try to implement the inverse logic and decrypt the QR, but we're too lazy for that, and I'm sure we're die debugging column vs row issues.

It's much easier to invert the key, because after all if we do swaps in reverse order, it should get us back the initial state!

```python
res = []
for line in open('key', 'r').readlines():
    line = line[:-1]
    res.append(line)
result = "\n".join(res[::-1])
open("invkey", 'w').write(result)
```

We can use this key to recover the [initial qr](decoded.txt).

Now we need to actually make a QR which some reader can decode for us, we went with PIL for that:

```python
from PIL import Image

qr = []
for line in open('decoded.txt', 'r').readlines():
    line = line[:-1]
    qr.append(line)

new = Image.new("RGB", (25, 25), (255, 255, 255))
for i in range(25):
    for j in range(25):
        if qr[i][j] == '1':
            new.putpixel((i, j), (0, 0, 0))
new.save("out.png")
```

From this we get a nice picture:

![](out.png)

Which decodes to: `zer0pts{puzzl3puzzl3}`
