# Katherine (crypto, 486p, 4 solved)

## Description

```
The friends of the famous actress Katherine Ceta-Iones have something to hide. Can you find their secret?
```

In the task we get the [server source code](katherine.py)
We can also connect to remote server, where this code is running.

## Code analysis

The code seems a bit complex, but in general this is just a convoluted key exchange.
We can create our own public-private keypair and perform key exchange with the server if we want to.

The agreed shared secret is created from:

1. Ephemeral random keys exchange
2. DH exchange using our public/private keys

```python
    sharedkey_static = private_key.exchange(peer_publickey)
    # Lets also do an ephemeral key agreement for added forward secrecy
    ephemeralkey_bytes = urandom(32)
    ephemeralkey = x25519.X25519PrivateKey.from_private_bytes(ephemeralkey_bytes)
    ephemeral_publickey_encoded = encode_publickey(ephemeralkey)
    print("My ephemeral key is {}.".format(ephemeral_publickey_encoded))
    peer_ephemeralkey_encoded = input("What is yours? ")
    peer_ephemeralkey = get_peer_publickey(peer_ephemeralkey_encoded)
    if(not peer_ephemeralkey):
        print("Bad key")
        exit(-1)
    sharedkey_ephemeral = ephemeralkey.exchange(peer_ephemeralkey)
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(sharedkey_static)
    digest.update(sharedkey_ephemeral)
    sharedkey = digest.finalize()
```

The issue here is that we need to impersonate owner of given public key, but we don't have his private key.
This means we can't get the `sharedkey_static` part.

## Vulnerabilities

The task description is hinting at KCI - Key Compromise Impersonation attack.
The idea of such attack is rather simple -> notice that if we know the `server` private key, we can easily do `sharedkey_static = server_private_key.exchange(peer_publickey)` for any public key we provide.
This means that knowing `server` private key allows us to impersonate anyone to this particular server!

Now the issue is how do we get server private key?
Well this was a bit guessy, because the code did not contain the server key generation logic.
However if we are very observant we can notice the argument name in:

```python
def get_server_privatekey(pin: str) -> x25519.X25519PrivateKey:
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(pin.encode())
    privatekey_bytes = digest.finalize()
    return x25519.X25519PrivateKey.from_private_bytes(privatekey_bytes)
```

The argument is called `pin`, so perhaps the seed for server key is in fact some short number?
We can try to brute-force it and compare public key with what we get from the server.
This turns out to be the case.

## Solver

### Server key recovery

First stage is to get private key of the server:

```python
def break_server_privkey():
    server_pubkey = 'ZIggNb0BcxBYnplA+AQNehxlUG8/x0okCfFJnoHZFFA='
    for i in range(9999):
        key = get_server_privatekey(str(i))
        p = encode_publickey(key)
        if p == server_pubkey:
            print(i)
            break
```

After a moment we get `7741`

### Getting the flag

Now we simply need to perform the key exchange, just replacing the `sharedkey_static` creation by value created from servver private key and target public key.
Rest is simply copied from the server code:

```python
def main():
    server_privkey = get_server_privatekey(str(7741))
    target_p = 'SgZSsPzLpfoEqnJojn+lftJekF7Q0yKYqcGSAOL2cyM='
    target_pubkey = x25519.X25519PublicKey.from_public_bytes(target_p.decode('base64'))
    sharedkey_static = server_privkey.exchange(target_pubkey)

    host = "pwn.institute"
    port = 36667
    s = nc(host, port)
    print(receive_until(s, "?"))
    send(s, "2")
    print(receive_until(s, ":"))
    send(s, target_p)

    ephemeralkey_bytes = os.urandom(32)
    ephemeralkey = x25519.X25519PrivateKey.from_private_bytes(ephemeralkey_bytes)
    ephemeral_publickey_encoded = encode_publickey(ephemeralkey)

    peer_ephemeralkey_encoded = receive_until(s, ".")[20:-1]
    peer_ephemeralkey = x25519.X25519PublicKey.from_public_bytes(peer_ephemeralkey_encoded.decode('base64'))

    sharedkey_ephemeral = ephemeralkey.exchange(peer_ephemeralkey)
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(sharedkey_static)
    digest.update(sharedkey_ephemeral)
    sharedkey = digest.finalize()

    print(receive_until(s, "?"))
    send(s, ephemeral_publickey_encoded)
    print(receive_until(s, ":"))
    challenge = receive_until(s, "\n").decode("base64")

    print(receive_until(s, "?"))
    mac = hmac.HMAC(sharedkey, hashes.SHA3_256(), backend=default_backend())
    mac.update(challenge)
    expected_response = base64.b64encode(mac.finalize()).decode("ascii")
    send(s, expected_response)
    interactive(s)


main()
```

After this we get `BCTF{K3y_c0mprom1se_iMp3rs0nation_we11_d0ne}`
