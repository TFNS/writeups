# Dive in the lake (re)

## Introduction

In the task we get a very simple [binary](dive).
There is not much code there, but interestingly the binary is equipped with debugging information.

## Analysis

Looking at this binary in disassembler is very confusing, because it seems the `flag check` logic was removed by compiler in optimization phase and it's no longer present:

```c
long f(long param_1,long param_2,long param_3)

{
  return param_1 + param_2 + param_3;
}

void main(int argc,char **argv)

{
  long lVar1;
  long lVar2;
  long lVar3;
  
  lVar1 = strtol(argv[1],(char **)0x0,10);
  lVar2 = strtol(argv[2],(char **)0x0,10);
  lVar3 = strtol(argv[3],(char **)0x0,10);
  f(lVar1,lVar2,lVar3);
  return;
}
```

If we attach a debugger we can see in the function `f`:

```
gef  info locals
flag = <optimized out>
gef  p flag
$5 = <optimized out>
```

So there was something there, but it's gone now.
The idea is that maybe the debugging information contains something we could use.

## Solution

It took us a while to figure this out, because readelf and objdump didn't want to cooperate with dwarf v5 debugging information.
Finally we managed to get something interesting by using `pyelftools` and `dwarfinfo`.

From `location list` section we managed to get:

```
DW_OP_const1u 1
DW_OP_breg5+0
DW_OP_breg4+0
DW_OP_and
DW_OP_breg1+0
DW_OP_and
DW_OP_const8u 7219272754963824708
DW_OP_ne
DW_OP_bra 3
DW_OP_const1u 3
DW_OP_mul
DW_OP_const8u 9259542123273814144
DW_OP_dup
DW_OP_dup
DW_OP_breg5+0
DW_OP_and
DW_OP_const1u 0
DW_OP_ne
DW_OP_bra 26
DW_OP_breg4+0
DW_OP_and
DW_OP_bra 9
DW_OP_breg1+0
DW_OP_and
DW_OP_bra 3
DW_OP_const1u 3
DW_OP_mul
DW_OP_breg5+0
DW_OP_dup
DW_OP_mul
DW_OP_breg4+0
DW_OP_dup
DW_OP_mul
DW_OP_plus
DW_OP_const8u 18116903027530606121
DW_OP_ne
DW_OP_bra 3
DW_OP_const1u 3
DW_OP_mul
DW_OP_breg1+0
DW_OP_dup
DW_OP_mul
DW_OP_breg4+0
DW_OP_dup
DW_OP_mul
DW_OP_plus
DW_OP_const8u 16612709672999228116
DW_OP_ne
DW_OP_bra 3
DW_OP_const1u 7
DW_OP_mul
DW_OP_const1u 189
DW_OP_eq
DW_OP_stack_value
```

and by the help of opcode descriptions in https://opensource.apple.com/source/lldb/lldb-167.2/source/Expression/DWARFExpression.cpp.auto.html we managed to figure out that this is the logic we're looking for, however it's written using dwarf stack-machine syntax.

Values pushed from DW_OP_breg5+0,DW_OP_breg4+0 and DW_OP_breg1+0 are simply our inputs to `f` function (passed in rdi, rsi and rdx).
So the code would perform some operations and checks on our inputs.
We can see that there are branches with some constant comparison, which skip `mul` instructions, eg:

```
DW_OP_const8u 18116903027530606121
DW_OP_ne
DW_OP_bra 3
DW_OP_const1u 3
DW_OP_mul
```

if top of the stack is not equal to 18116903027530606121 we will jump 3 instructions ahead, skipping multiplication of new stack top by 3

At the end of the code we can see:

```
DW_OP_const1u 189
DW_OP_eq
```

so we expect to have 189 at the end, and we start with `DW_OP_const1u 1`.
189 factors into `3*3*3*7` and we have exactly three multiplications by 3 and one by 7, which simply means we can't skip any of them.
This means we need to pass all `DW_OP_ne` comparisons.

### Check 1

```
DW_OP_breg5+0
DW_OP_breg4+0
DW_OP_and
DW_OP_breg1+0
DW_OP_and
DW_OP_const8u 7219272754963824708
DW_OP_ne
```

is `x&y&z != 7219272754963824708`

### Check 2

```
DW_OP_const8u 9259542123273814144
DW_OP_dup
DW_OP_dup
DW_OP_breg5+0
DW_OP_and
DW_OP_const1u 0
DW_OP_ne
DW_OP_bra 26
DW_OP_breg4+0
DW_OP_and
DW_OP_bra 9
DW_OP_breg1+0
DW_OP_and
DW_OP_bra 3
```

is `x&9259542123273814144 !=0`, `y&9259542123273814144 !=0`, `z&9259542123273814144 !=0`

### Check 3

```
DW_OP_breg5+0
DW_OP_dup
DW_OP_mul
DW_OP_breg4+0
DW_OP_dup
DW_OP_mul
DW_OP_plus
DW_OP_const8u 18116903027530606121
DW_OP_ne
```

is `x*x + y*y != 18116903027530606121`

### Check 4

```
DW_OP_breg1+0
DW_OP_dup
DW_OP_mul
DW_OP_breg4+0
DW_OP_dup
DW_OP_mul
DW_OP_plus
DW_OP_const8u 16612709672999228116
DW_OP_ne
```

is `y*y+z*z != 16612709672999228116`

### Solver

Now that we know all the constraints we can feed them into z3:

```python
    solver = z3.Solver()
    x = BitVec("x", 64)
    y = BitVec("y", 64)
    z = BitVec("z", 64)
    solver.add(x & y & z == 7219272754963824708)
    solver.add(x & 9259542123273814144 == 0)
    solver.add(y & 9259542123273814144 == 0)
    solver.add(z & 9259542123273814144 == 0)
    solver.add(x * x + y * y == 18116903027530606121)
    solver.add(z * z + y * y == 16612709672999228116)
    print(solver.check())
    model = solver.model()
    f = long_to_bytes(model[z].as_long())
    f += long_to_bytes(model[y].as_long())
    f += long_to_bytes(model[x].as_long())
    print(f[::-1])
```

and we get `EPFL{_1tTookS3venDwarf5}`
