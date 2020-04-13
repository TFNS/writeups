# Autobot (re, 281p)

In the challenge we can connect to a server, and we get back a base64 encoded [payload](payload.txt).
Then the server is waiting for some input from us.

If we decode the payload, we can see it's an ELF binary, which is performing a simple input-checking:

```c
  int i;
  int indices [23];
  char user_input [23];
  
  indices[0] = 0x15;
  indices[1] = 5;
  indices[2] = 4;
  indices[3] = 0xb;
  indices[4] = 0x10;
  indices[5] = 0x16;
  indices[6] = 0xd;
  indices[7] = 2;
  indices[8] = 0xc;
  indices[9] = 6;
  indices[10] = 0;
  indices[11] = 0x13;
  indices[12] = 1;
  indices[13] = 9;
  indices[14] = 0xe;
  indices[15] = 0x14;
  indices[16] = 7;
  indices[17] = 0x11;
  indices[18] = 8;
  indices[19] = 0xf;
  indices[20] = 10;
  indices[21] = 0x12;
  indices[22] = 3;
  fgets(user_input,0x18,stdin);
  i = 0;
  while (i < 0x17) {
    if (user_input[i] != some_constant_data[indices[i]]) {
      puts("Wrong pass");
      exit(1);
    }
    i = i + 1;
  }
  printf("good job");
```

It's pretty simple, there is a constant string in memory, and some permutation of indices, and our input has to match the data ordered by this permutation.
The trick is that once we submit the answer, we get another payload to solve!

All payloads follow the same structure, the only differences are:

- size of the constant string (up to about 30 bytes)
- index permutation

The goal is to make a script which will automatically solve those crackmes.
It probably would be easy to use angr, but we went ahead with even easier approach:

First find the contant string in the binary, because it's always right before `Wrong pass` string:

```python
def extract_constant(raw_data):
    end_index = raw_data.index("Wrong pass") - 2
    start = end_index
    while True:
        if raw_data[start] != '\0':
            start -= 1
        else:
            start += 1
            break
    pass_array = raw_data[start:end_index + 1]
    return pass_array
```

Then use objdump to dump the assembly, and then parse the permutation.
Permutation is very easy to find:

```asm
 7f4:	c7 85 20 ff ff ff 15 	movl   $0x15,-0xe0(%rbp)
 7fb:	00 00 00 
 7fe:	c7 85 24 ff ff ff 0b 	movl   $0xb,-0xdc(%rbp)
 805:	00 00 00 
 808:	c7 85 28 ff ff ff 0e 	movl   $0xe,-0xd8(%rbp)
 80f:	00 00 00 
 812:	c7 85 2c ff ff ff 17 	movl   $0x17,-0xd4(%rbp)
 819:	00 00 00 
 81c:	c7 85 30 ff ff ff 11 	movl   $0x11,-0xd0(%rbp)
```

We can just find regex matching those `movl`.

```python
def solve(data):
    raw_data = data.decode("base64")
    open("out.bin", 'wb').write(raw_data)
    os.system("objdump -d out.bin > res.txt")
    instructions = open("res.txt", 'r').read()
    indices = re.findall("movl\s+\\$0x(.*),.*", instructions)[:-1]
    length = int(indices[-1], 16)
    indices = map(lambda x: int(x, 16), indices[:-1])
    pass_array = extract_constant(raw_data)
    password = "".join([pass_array[indices[i]] for i in range(length)])
    return password
```

We plug this solver to communicate with server:

```python
def main():
    port = 6000
    host = "pwn.byteband.it"
    s = nc(host, port)
    while True:
        data = receive_until(s, "\n")
        print(data)
        password = solve(data)
        send(s, password)
```

And after some time we get `flag{0pt1mus_pr1m3_has_chosen_you}`
