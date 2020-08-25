# Basics (hardware, 50p, 280 solved)

## Description

In the task we get 2 source files:
- [main](main.cpp)
- [system verilog checker](check.sv)

We can also connect to remote server, where this code is running.

## Static code analysis

### Main

Main is pretty simple:
1. Read input character
2. Strip most significant bit
3. Feed to the circuit
4. Simulate clock tick, so the input goes through the circuit
5. Loop at most 100 times, or when user provides newline
6. Check the state of `check->open_safe` circuit outpupt, and give the flag

Note: since the flag is sent when we match input to the circuit, it's safe to assume that our input is NOT the flag, but rather some random string.

### Password checker

The important part here is the system verilog circuit which verifies the password.
Since we don't know it, we just tried to guess-timate /check the syntaxt and re-write this logic into python.

Input is marked as:
```
input [6:0] data
```
so there are 7 bits of input, which matches what `main` is feeding.

Then we have:

```verilog
reg [6:0] memory [7:0];
```

So memory is 8 element array of 7 bit registers.
Enough to hold 8 bytes of input.

There is also:

```verilog
reg [2:0] idx = 0;
```
So 3 bit register for holding index, therefore it's enough to count 0..7, as much as our input array can have.

This all suggests password length of 8.

Next entry is:

```verilog
wire [55:0] magic = {
    {memory[0], memory[5]},
    {memory[6], memory[2]},
    {memory[4], memory[3]},
    {memory[7], memory[1]}
};
```

This is 56 bit array, created by concatenation of values in `memory`, so our inputs.
It concatenates pairs of input bytes, and then combines this in a single bitstream.
Keep in mind bit order during this concatenation!
It is:

```
memory[0][7], ..., memory[0][0], memory[1][7], ...,memory[1][0]
```

Where `memory[0][7]` is MSB and `memory[0][0]` is LSB of `memory[0]` entry.

This is important, because if you hold a binary value in, for example, python, bit order is inverted compared to this!
Eg. `D` is `68` or `0b1000100`, but in such case `val[0]` would return MSB and not LSB.

Then we have:

```verilog
wire [55:0] kittens = { magic[9:0],  magic[41:22], magic[21:10], magic[55:42] };
```

Again a 56 bit array, created by concatenating bits from `magic` array.

Then state of the password checker is done via:

```verilog
assign open_safe = kittens == 56'd3008192072309708;
```

So basically `kittens` have to be equal to this 56 bit decimal number `3008192072309708`

Lastly we have:

```verilog
always_ff @(posedge clk) begin
    memory[idx] <= data;
    idx <= idx + 5;
end
```

So data are not filling memory in consecutive order.
Notice that `idx` is bumped by 5, and we know `idx` is counting `mod 8`, so we're filling memory in order 0, 5, 2, 7, 4, 1, 6, 3

### Pythonized checker

Now that we know what the checker does, we can implement this in python:

```python
def encrypt(input_data):
    memory = [None for _ in range(8)]
    idx = 0
    for data in input_data:
        memory[idx] = bin(ord(data)).replace("0b", "").rjust(7, '0')
        idx = (idx + 5) % 8
    magic = memory[0] + memory[5] + memory[6] + memory[2] + memory[4] + memory[3] + memory[7] + memory[1]
    magic = magic[::-1]  # if we access via index magic[0] is LSB not MSB as in our string magic, so invert here
    kittens = magic[0:10][::-1] + magic[22:42][::-1] + magic[10:22][::-1] + magic[42:56][::-1] # each bit chunk has inverted bit order
    res = int(kittens, 2)
    return res
```

## Solver

Now we need to implement inverse function.

First we can just turn output value into bitstream, and then we want to get back from `kittens` to `magic`:

```python
def recover_magic(kittens):
    idx = 0
    magic = [None for _ in range(56)]
    for i in range(9, -1, -1):
        magic[i] = kittens[idx]
        idx += 1
    for i in range(41, 21, -1):
        magic[i] = kittens[idx]
        idx += 1
    for i in range(21, 9, -1):
        magic[i] = kittens[idx]
        idx += 1
    for i in range(55, 41, -1):
        magic[i] = kittens[idx]
        idx += 1
    magic = magic[::-1]
    magic = ''.join(magic)
    return magic
```

We know which bit ranges where going to next kittens bits, so we can read them back.

Rest of the decryption is quite simple.
Once we have `magic`, we can split it in 7-bit blocks, and put them back in original order.
Finally we want to invert the permutation introduced by `idx+5 %8`:

```python
def decrypt(target):
    kittens = bin(target).replace("0b", "").rjust(56, '0')
    magic = recover_magic(kittens)
    chunks = chunk(magic, 7)
    memory = [chunks[0], chunks[7], chunks[3], chunks[5], chunks[4], chunks[1], chunks[2], chunks[6]]
    shuffled_input = [chr(int(x, 2)) for x in memory]
    input_perm = [0, 5, 2, 7, 4, 1, 6, 3]
    res = [None for _ in range(8)]
    for i, s in enumerate(input_perm):
        res[s] = shuffled_input[i]
    return ''.join(res)
```

We can check this with a simple sanity check:

```python
def sanity():
    input_data = "ABCDEFGH"
    enc = encrypt(input_data)
    dec = decrypt(enc)
    assert input_data == dec

sanity()
```

So if we reversed the checker logic correctly, our decrypt should be valid as well.
There is only one way to find out -> decrypt 3008192072309708 and send to the server.
Decryption gives `7LoX%*_x` and if we submit this to the server we get `CTF{W4sTh4tASan1tyCh3ck?}`
