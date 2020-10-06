# BabypadV2 (crypto, 484p, 7 solved)

## Description

We get [source code](chall.py) and address of remote service running this.
The source is not very useful, since the important part is a blackbox.

## Code analysis

The application is generating random values via some special blackbox and then encrypts the flag with XOR.
So it's essentially a stream cipher.

We can ask how many times we want to encrypt the flag, and we receive `31*n` bytes as response, so flag is `31` bytes long.

### RNG

While the random is secret we do know that:

- it's returning double values, which then are turned into 8 bytes to be used as keystream
- the values are supposed to be `measured directly from our quantum flux generator`

## Vulnerability

Issue here is not very obvious or clear, and requires a bit of guessing and `recon`.
If we look at last year's `Babypad` it seems to be a similar problem, however in this particular case the keystream generator was omitting returning byte `\0`.
This is a fatal flaw, since you can ask for many ciphertexts and if byte at `k-th` position got encrypted to all values but one, you know this is the `real` value.

A similar issue is present here, although it's a bit more complicated.
It turns out that the RNG returns all `normal` double values, except for `special` ones like `INF` and `NaN`.

## Attack outline

Let's look at:  https://en.wikipedia.org/wiki/Double-precision_floating-point_format#Double-precision_examples

It's clear that we get `INF/NaN` in case all 11 bits of exponent at set to `1` and sign bit is 0 or 1.

So we can have a look at 2 consecutive bytes of a flag.
Let's assume we know the first one (eg. from flag prefix).
If first byte was `xored` with `0b11111111` or `0b01111111` then the next byte could not have been xored with `0b11110000` because it would mean xoring with `INF` or `NaN`.

We could make inverse observation as well -> if we know the second byte (eg. flag suffix), we can deduce that if this byte was xored with `0b11110000` then first byte could not have been xored with `0b01111111` or `0b11111111`.

We can, therefore, observe many encryptions, and mark all impossible characters.
This way after enough observations we should be able to pinpoint the only remaning last value.

Sanity check:

```python
def sanity():
    vals = set([chr((0b11111111 ^ c)) for c in range(256) if chr(c) not in string.printable])
    secret = 'x'
    while len(vals) < 255:
        keystream = os.urandom(8)
        f = struct.unpack("d", keystream)[0]
        if math.isnan(f):
            pass
        elif ord(keystream[6]) & 0b11110000 == 0b11110000:
            res = xor_string(keystream[7], secret)
            vals.add(res)
    for c in range(256):
        if chr(c) not in vals:
            result = chr((c ^ 0b11111111) & 0b01111111)
            print(c, result)
            assert result == secret


sanity()
```

This seems to work just fine.

### Shifting keystream

There is one small issue we skipped so far.
Notice that we can only recover bytes encrypted using 7th and 8th byte of the 8byte chunk generated from a single double value.
We need to expand this somehow to all characters.

You may remember that we can ask the server to encrypt the flag `n` times for us.
The flag is `31` bytes long, and keystream chunks are `8` bytes long.
This means that after single encryption of the flag, there is still 1 keystream byte not `consumed`.
If we request 2 encryptions, this leftover byte will be used to encrypt first char of the second flag encryption, and then rest of the flag will be encrypted with `shifted` bytes of the `double`.

This way we can shift the keystream to any position we want.
Encrypting 8 times will reset the position to offset 0.

### Slow solver

Our first attempt at the solver was exectly as described above, using the forward prediction:

```python
def main():
    host = 'okboomer.tasteless.eu'
    port = 10501
    # host = 'localhost'
    # port = 1337
    s = nc(host, port)
    charset = string.letters + string.digits + "?!_"
    ref_values = [chr((0b11111111 ^ c)) for c in range(256) if chr(c) not in charset]
    flag_len = 31
    known_flag = "tstlss{"
    needed_to_zero = 8
    for i in range(len(known_flag) - 7, flag_len - 7):
        values = set(ref_values)
        needed = i % 8
        left = needed_to_zero - needed - 1
        start = time()
        while len(values) < 255:
            print(i, len(values), known_flag)
            # shift
            s.sendall(str(needed).ljust(4, " "))
            response = ''
            while len(response) < needed * flag_len:
                response += s.recv(9999)

            # get value
            s.sendall(str(1).ljust(4, " "))
            response = ''
            while len(response) < flag_len:
                response += s.recv(9999)

            keystream = xor_string(response, known_flag)
            if (ord(keystream[6 + i]) & 0b11110000) == 0b11110000:
                encoded_byte = response[7 + i]
                values.add(encoded_byte)

            # shift to zero
            s.sendall(str(left).ljust(4, " "))
            response = ''
            while len(response) < left * flag_len:
                response += s.recv(9999)
        for c in range(256):
            if chr(c) not in values:
                known_flag += chr((c ^ 0b11111111) & 0b01111111)
                print(c, chr((c ^ 0b11111111) & 0b01111111), known_flag, time() - start)
    s.close()
    print(known_flag)


main()
```

This worked, however it was recovering single byte for 20 minutes.
It would take a few hours at this pace, so we decided to maybe improve this a bit...

### Optimized solver

Notice that the naive solver is basically `wasting` a lot of data.
We don't even look at payloads recovered during `shifting` at all, even though they could be useful to recover some next bytes.
We also don't do the `backwards` lookup.
In reality it's possible to be concurrently collecting data for multiple bytes at the same time:

```python
def main():
    host = 'okboomer.tasteless.eu'
    port = 10501
    p = remote(host, port)

    charset = string.printable
    flag_len = 31
    step = 8
    check = 6

    known_prefix = 'tstlss{'
    flag_chars = []
    flag = []

    for char in known_prefix:
        flag.append(char)
    for _ in range(flag_len - len(flag)):
        flag.append(None)

    flag[-1] = '}'

    for _ in range(flag_len):
        flag_chars.append(set(c for c in string.printable))
    threshold = 8000
    
    while any(list(map(lambda s: len(s) > 1, flag_chars))):
        output = b''
        try:
            output = b''
            p.sendline(str(threshold).encode())
            while len(output) < threshold * flag_len:
                output += p.recv(threshold * flag_len - len(output))
        except:
            p = remote(host, port)
        for check_idx in range(check, len(output) - 1, 8):
            # inf, nan
            markers = [0xf0, 0xf8]
            if flag[check_idx % flag_len] is not None and output[check_idx] ^ ord(flag[check_idx % flag_len]) in markers:
                char_idx = (check_idx + 1) % flag_len
                try:
                    impossible_val = output[check_idx + 1] ^ 0x7f
                    flag_chars[char_idx].remove(chr(impossible_val))
                except:
                    pass
            elif flag[(check_idx + 1) % flag_len] is not None and output[check_idx + 1] ^ ord(flag[(check_idx + 1) % flag_len]) == 0x7f:
                char_idx = check_idx % flag_len
                try:
                    for m in markers:
                        impossible_val = output[check_idx] ^ m
                        flag_chars[char_idx].remove(chr(impossible_val))
                except:
                    pass
        flag_str = ''
        print('Lengths:', list(map(len, flag_chars)))
        for i in range(flag_len):
            s = flag_chars[i]
            if len(s) == 1:
                flag_str += list(s)[0]
                flag[i] = list(s)[0]
            else:
                flag_str += 'X'
        print(f'Current flag: {flag_str}')
        print(f'As list: {flag}')

main()
```

This speeds up to just a few minutes per character and finally we get `tstlss{wh4t3v3r_fl04t5_ur_g04t}`

