# Integral Communication - IrisCTF 2024 (crypto, 82 solved, 197p)

## Introduction
Integral Communication is a cryptography task.

A Python script implementing an echo server is given.

## Analysis
The script implements a server that encrypts commands and execute encrypted
commands.

There are two commands: `echo` that prints a message and `flag` that prints the
flag.

It is possible to sign an `echo` command from user `guest` with an arbitrary
message.

```python
def create_command(message: str) -> (str, str):
    payload = {"from": "guest", "act": "echo", "msg": message}
    payload = dumps(payload).encode()
    while len(payload) % 16 != 0:
        payload += b'\x00'
    iv, payload = encrypt(payload)
    return hexlify(iv).decode('utf-8'), hexlify(payload).decode('utf-8')
```

The commands are encoded with JSON and look like this:
```json
{"from": "guest", "act": "echo", "msg": "Hello world!"}
```

The messages are encrypted with `AES` with a random 128-bit key in `CBC` mode
and random iv.
```python
key = get_random_bytes(16)


def encrypt(plaintext: bytes) -> (bytes, bytes):
    iv = get_random_bytes(16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    print("IV:", hexlify(iv).decode())
    return iv, aes.encrypt(plaintext)
```

In order to obtain the flag, one has to provide an encrypted `flag` command from
user `admin`.

## Exploitation
The goal of this challenge is to flip a few bits from an encrypted message
```
{"from": "guest", "act": "echo", "msg": "x"}
{"from": "admin", "act": "flag", "msg": "x"}
```

Since the data is encrypted with CBC, the decryption algorithm will do something
like this:
```python
block[0] = aes_decrypt(input[0:16]) ^ iv
block[1] = aes_decrypt(input[16:32]) ^ input[0:16]
block[2] = aes_decrypt(input[32:48]) ^ input[16:32]
...
```

It is possible to change the content of `block[1]` to any value by setting
`input[0:16]` to be `block[1] ^ input[0:16] ^ target`, however this will break
`block[0]`, obviously.

It is possible to fix `block[0]` the same way: by changing the IV to be
`block[0] ^ iv ^ target`.

However, changing `input[0:16]` to update `block[1]` will change the value of
`block[0]`. It would not be possible to know this information without having the
key.

Fortunately, whenever a decryption happens, if the message is not valid UTF-8,
the server will print the content of the decrypted message.

```
Failed to decode UTF-8:
c9ad0edbf47fd84d4fd0dc9be55df689
2c2022616374223a2022666c6167222c
20226d7367223a202278227d

00000000: c9 ad 0e db f4 7f d8 4d 4f d0 dc 9b e5 5d f6 89  .......MO....]..
00000010: 2c 20 22 61 63 74 22 3a 20 22 66 6c 61 67 22 2c  , "act": "flag",
00000020: 20 22 6d 73 67 22 3a 20 22 78 22 7d               "msg": "x"}
```

The final exploit first sends a message with an invalid `block[0]` to retrieve
the value of `block[0]` after modification of the input and then sends a second
message with the correct IV to fix the whole message.

```
== proof-of-work: disabled ==
---------------------------------------------------------------------------
1. Create command
2. Run command
3. Exit
---------------------------------------------------------------------------
> 1
Please enter your message: x
IV: 2625ce0318dc2aed289706c1b3f20048
IV: 2625ce0318dc2aed289706c1b3f20048
Command: 4d0c7ccc552a223a0ca2da4300dadf0d3ca6a3e3623bb9d89d36d20724201be0ca777aed57acd74fb580f7b2d8e28931
---------------------------------------------------------------------------
1. Create command
2. Run command
3. Exit
---------------------------------------------------------------------------
> 2
IV: 2625ce0318dc2aed289706c1b3f20048
Command: 4d0c7ccc552a223a0ca2d94c09d2df0d3ca6a3e3623bb9d89d36d20724201be0ca777aed57acd74fb580f7b2d8e28931
Failed to decode UTF-8: c9ad0edbf47fd84d4fd0dc9be55df6892c2022616374223a2022666c6167222c20226d7367223a202278227d
---------------------------------------------------------------------------
1. Create command
2. Run command
3. Exit
---------------------------------------------------------------------------
> 2
IV: 94aaa6aa83ced09a4765bb3e3bc698e3
Command: 4d0c7ccc552a223a0ca2d94c09d2df0d3ca6a3e3623bb9d89d36d20724201be0ca777aed57acd74fb580f7b2d8e28931
Congratulations! The flag is: irisctf{cbc_d03s_n07_m34n_1n73gr1ty}
```

**Flag**: `irisctf{cbc_d03s_n07_m34n_1n73gr1ty}`

## Appendices
### pwn.php
```php
<?php
$iv  = "2625ce0318dc2aed289706c1b3f20048";
$cmd = "4d0c7ccc552a223a0ca2da4300dadf0d3ca6a3e3623bb9d89d36d20724201be0ca777aed57acd74fb580f7b2d8e28931";

$iv  = hex2bin($iv);
$cmd = hex2bin($cmd);

$blocks = str_split($cmd, 0x10);

$old = '{"from": "guest", "act": "echo", "msg": "x"}' . str_repeat("\x00", 4);
$new = '{"from": "admin", "act": "flag", "msg": "x"}' . str_repeat("\x00", 4);

$bold = str_split($old, 16);
$bnew = str_split($new, 16);

$old = $bold[1];
$new = $bnew[1];

for($i = 0; $i < strlen($old); $i++)
	$cmd[$i] = $cmd[$i] ^ $old[$i] ^ $new[$i];

printf("IV:  %s\n", bin2hex($iv));
printf("cmd: %s\n", bin2hex($cmd));

// Failed to decode UTF-8
$old = hex2bin("c9ad0edbf47fd84d4fd0dc9be55df6892c2022616374223a2022666c6167222c20226d7367223a202278227d");
$old = substr($old, 0, 0x10);

//$old = $bold[0];
$new = $bnew[0];

for($i = 0; $i < strlen($old); $i++)
	$iv[$i] = $iv[$i] ^ $old[$i] ^ $new[$i];

printf("IV:  %s\n", bin2hex($iv));
printf("cmd: %s\n", bin2hex($cmd));
```
