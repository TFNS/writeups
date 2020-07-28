# Polyglot (re/misc, 50p, 171 solved)

The challenge is sort-off matrioshka.

## Stage 1

We start off with some [C code](code.c), which we can simply compile and run.
It expects:

```c
char *key = getenv("XKEY");
if((!key) ||strncmp("mod3r0d!",key,8 )){
    puts(";[");
    return 1;
}
```

So we can for simplicity just set `char *key  = "mod3r0d!";` and run it.
This spits out [some C++ code](code2.cpp)

## Stage 2

This stage is very similar - we have code, which should drop another stage.
The issue here is that the code is unrolling some recursive templates at compile time and we need to optimize this.
We have:

```cpp
template <unsigned int a, unsigned int b>
struct t1 {
	enum { value = b + t1<a-1, b>::value };
};
template <unsigned int b>
struct t1<0, b> {
	enum { value = 0 };
};
template <unsigned int a, unsigned int b>
struct t2 {
	enum { value = 1 + t2<a-1, b>::value };
};
template <unsigned int b>
struct t2<0, b> {
	enum { value = 1 + t2<0, b-1>::value };
};
template<>
struct t2<0, 0>{
    enum { value = 0};
};
```

And we need the value of:

```cpp
t2<0xcaca0000, t2<444, t1<t2<100, t1<4,3>::value>::value, t2<44, t1<11,3>::value>::value>::value>::value>::value
```

### t1 optimization

If we write down `t1` in simple recursive notation we have:

```python
def t1(a,b):
    if a == 0:
        return 0
    else:
        return b + t1(a-1,b)
```

So it simply adds `b` to the result `a` times, hence `a*b`

### t2 optimization

We do similar exercise for `t2`:

```python
def t2(a,b):
    if a == 0 and b == 0:
        return 0
    elif a == 0:
        return 1 + t2(0, b-1)
    else:
        return 1 + t2(a-1,b)
```

So it basically adds `1` to the result `a` times, and once `a == 0` it adds `1` to the sum `b` times, hence `a+b`

### Wrap up

Now we can simply calculate the constant to be `3402244972` and compile and run the code to drop last stage.

## Stage 3

Last stage generates some [python functions](code3.py) from pure bytecode and runs them.
We can either just do `dis.dis(f1)` on them, try with uncompyle or just blackbox to figure out that the functions are:

- f1 compares 2 arguments for equality
- f2 calls `ord(argument)`
- f3 calls `input()`
- f4 is actual flag checker
- f5 is just main which uses f4 and prints if we got the right flag or not

The only really important part is `f4` where the real logic is located:

Load lots of int constants.
```
  0 LOAD_CONST               1 (99)
  2 LOAD_CONST               2 (121)
  4 LOAD_CONST               3 (98)
  6 LOAD_CONST               4 (114)
  8 LOAD_CONST               5 (105)
 10 LOAD_CONST               1 (99)
 12 LOAD_CONST               6 (115)
 14 LOAD_CONST               7 (123)
 16 LOAD_CONST               8 (52)
 18 LOAD_CONST               9 (97)
 20 LOAD_CONST               3 (98)
 22 LOAD_CONST              10 (100)
 24 LOAD_CONST              11 (51)
 26 LOAD_CONST              12 (101)
 28 LOAD_CONST              13 (55)
 30 LOAD_CONST               8 (52)
 32 LOAD_CONST              12 (101)
 34 LOAD_CONST              14 (57)
 36 LOAD_CONST              12 (101)
 38 LOAD_CONST              15 (53)
 40 LOAD_CONST              14 (57)
 42 LOAD_CONST              16 (54)
 44 LOAD_CONST              17 (48)
 46 LOAD_CONST               9 (97)
 48 LOAD_CONST              18 (49)
 50 LOAD_CONST               3 (98)
 52 LOAD_CONST              16 (54)
 54 LOAD_CONST               3 (98)
 56 LOAD_CONST              14 (57)
 58 LOAD_CONST              19 (50)
 60 LOAD_CONST              11 (51)
 62 LOAD_CONST              10 (100)
 64 LOAD_CONST              20 (56)
 66 LOAD_CONST               8 (52)
 68 LOAD_CONST              19 (50)
 70 LOAD_CONST               1 (99)
 72 LOAD_CONST               1 (99)
 74 LOAD_CONST              10 (100)
 76 LOAD_CONST               9 (97)
 78 LOAD_CONST               1 (99)
 80 LOAD_CONST              18 (49)
 82 LOAD_CONST              11 (51)
 84 LOAD_CONST              16 (54)
 86 LOAD_CONST              15 (53)
 88 LOAD_CONST              20 (56)
 90 LOAD_CONST               3 (98)
 92 LOAD_CONST              11 (51)
 94 LOAD_CONST              21 (102)
 96 LOAD_CONST              22 (125)
 98 BUILD_LIST              49
100 STORE_FAST               1 (v1)
 ```

Get length of the created constant list, and compare it with user input length.
If lengths don't match, return print error and return false.

```
102 LOAD_GLOBAL              0 (len)
104 LOAD_FAST                0 (v0)
106 CALL_FUNCTION            1
108 LOAD_GLOBAL              0 (len)
110 LOAD_FAST                1 (v1)
112 CALL_FUNCTION            1
114 COMPARE_OP               3 (!=)
116 POP_JUMP_IF_FALSE      130
118 LOAD_GLOBAL              1 (print)
120 LOAD_CONST              23 ('Length mismatch!')
122 CALL_FUNCTION            1
124 POP_TOP
126 LOAD_CONST              24 (False)
128 RETURN_VALUE
```

If lengths are matching, use zip to combine user input with constants list.
Use `f2` (ord) to get a number from each character of user input and then use `f1` (comparison) to check if the integer matches constant.
```
>>  130 LOAD_GLOBAL              2 (zip)
132 LOAD_FAST                0 (v0)
134 LOAD_FAST                1 (v1)
136 CALL_FUNCTION            2
138 GET_ITER
>>  140 FOR_ITER                36 (to 178)
142 STORE_FAST               2 (v2)
144 LOAD_GLOBAL              3 (f1)
146 LOAD_FAST                2 (v2)
148 LOAD_CONST              25 (1)
150 BINARY_SUBSCR
152 LOAD_GLOBAL              4 (f2)
154 LOAD_FAST                2 (v2)
156 LOAD_CONST              26 (0)
158 BINARY_SUBSCR
160 CALL_FUNCTION            1
162 CALL_FUNCTION            2
164 LOAD_CONST              24 (False)
166 COMPARE_OP               2 (==)
168 POP_JUMP_IF_FALSE      140
170 POP_TOP
172 LOAD_CONST              24 (False)
174 RETURN_VALUE
176 JUMP_ABSOLUTE          140
>>  178 LOAD_CONST              27 (True)
180 RETURN_VALUE
```

If everything matches, we got the right flag.

So we simply need to grab those constants and do `chr` on them:

```python
    data = """0 LOAD_CONST               1 (99)
  2 LOAD_CONST               2 (121)
  4 LOAD_CONST               3 (98)
  6 LOAD_CONST               4 (114)
  8 LOAD_CONST               5 (105)
 10 LOAD_CONST               1 (99)
 12 LOAD_CONST               6 (115)
 14 LOAD_CONST               7 (123)
 16 LOAD_CONST               8 (52)
 18 LOAD_CONST               9 (97)
 20 LOAD_CONST               3 (98)
 22 LOAD_CONST              10 (100)
 24 LOAD_CONST              11 (51)
 26 LOAD_CONST              12 (101)
 28 LOAD_CONST              13 (55)
 30 LOAD_CONST               8 (52)
 32 LOAD_CONST              12 (101)
 34 LOAD_CONST              14 (57)
 36 LOAD_CONST              12 (101)
 38 LOAD_CONST              15 (53)
 40 LOAD_CONST              14 (57)
 42 LOAD_CONST              16 (54)
 44 LOAD_CONST              17 (48)
 46 LOAD_CONST               9 (97)
 48 LOAD_CONST              18 (49)
 50 LOAD_CONST               3 (98)
 52 LOAD_CONST              16 (54)
 54 LOAD_CONST               3 (98)
 56 LOAD_CONST              14 (57)
 58 LOAD_CONST              19 (50)
 60 LOAD_CONST              11 (51)
 62 LOAD_CONST              10 (100)
 64 LOAD_CONST              20 (56)
 66 LOAD_CONST               8 (52)
 68 LOAD_CONST              19 (50)
 70 LOAD_CONST               1 (99)
 72 LOAD_CONST               1 (99)
 74 LOAD_CONST              10 (100)
 76 LOAD_CONST               9 (97)
 78 LOAD_CONST               1 (99)
 80 LOAD_CONST              18 (49)
 82 LOAD_CONST              11 (51)
 84 LOAD_CONST              16 (54)
 86 LOAD_CONST              15 (53)
 88 LOAD_CONST              20 (56)
 90 LOAD_CONST               3 (98)
 92 LOAD_CONST              11 (51)
 94 LOAD_CONST              21 (102)
 96 LOAD_CONST              22 (125)"""
    res = re.findall("(\d+) \((\d+)\)", data)
    result = []
    for x, y in res:
        result.append(int(y))
    print(result)
    print("".join(map(chr, result)))
```

And we get `cybrics{4abd3e74e9e5960a1b6b923d842ccdac13658b3f}`
