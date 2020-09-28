# Cryptosh (crypto, 486p, 4 solved)

## Description

In the task we get the [server source code](cryptsh.py)
We can also connect to remote server, where this code is running.

## Code analysis

The code allows us to do 2 things:

- Sign selected command
- Execute signed command

### Signing commands

We can only sign command form a selected list:

- exit
- echo
- ls

We can pass parameters to those commands, but they are escaped, so there is no way to do a simple shell injection here.
A valid command is signed by AES CBC-MAC and encrypted using AES-CTR with the same key, and nonce is actually equal to first 12 bytes of CBC IV.

The payload which is actually signed is `exec selected_command parameters`.

### Executing commands

We can submit any signed command, it will get decrypted, CBC-MAC will be checked and the command will get executed if it's valid.

## Vulnerability

Notice that both encryption methods used here have a very similar issue - they are prone to bitflipping attacks.
AES-CTR is a stream cipher, so a keystream is XORed with plaintext to get ciphertext, and vice versa.
This means that if we XOR `k-th` character of the ciphertext with value `X` then after decryption the plaintext will have `k-th` character XORed with value `X`.
So we can easily sign some payload, and then bitflip the ciphertext to get ciphertext for some plaintext of our choosing.

MAC is supposed to prevent this, however due to CBC mode it's not perfect.
In CBC mode ciphertext is XORed with IV after decryption to recover plaintext.
This means that if we XOR `k-th` byte of the IV with value `X` then after decryption `k-th` character of plaintext will be XORed with `X`.
We control IV so we can do that.

A small issue here is that first 12 bytes of IV are also used as CTR nonce, and therefore we cannot touch them, because if we do, the CTR keystream will change and our ciphertext will not decrypt properly anymore.

This means we can only modify last 4 characters of the IV, but this is more than enough to make a shell injection.
In fact we could pull this off with changing only 1 byte, by flipping something to `;`

## Solver

The idea is to:

1. Perform `sign_command echo AAAAA`, which will sign for us `exec echo AAAAA\1`.
2. XOR the ciphertext to get `exec echo AA;sh\1` instead.
3. XOR the IV in similar fashion.
4. Construct new payload and execute it

```python
def main():
    host = "pwn.institute"
    port = 36224
    s = nc(host, port)
    print(receive_until(s, '>'))
    send(s, "sign_command echo AAAAA")
    signed = receive_until(s, '>')[:-2]

    enc = base64.b64decode(signed)
    iv = enc[:BLOCK_SIZE]
    mac = enc[-BLOCK_SIZE:]
    data = enc[BLOCK_SIZE:-BLOCK_SIZE]

    padded_line = 'exec echo AAAAA\1'
    target = 'exec echo AA;sh\1'
    flips = xor_string(target, padded_line)

    new_data = xor_string(data, flips)
    new_iv = xor_string(iv, flips)
    new_payload = base64.b64encode(new_iv + new_data + mac)
    send(s, new_payload)

    interactive(s)

    send(s, "quit")
    print(receive_until(s, '.'))


main()
```

And we now have a reverse shell on the server which we can use to `cat flag` and get `BCTF{why_us3_SSH_wh3n_y0u_c4n_r0ll_y0ur_0wn_crypt0}`
