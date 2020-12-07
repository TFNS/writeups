# Bro64 (crypto/guessing, 143p, 51 solved)

## Description

```
Betaflash let’s go in Cuba and dance amigo !!

Flag format: CTF{sha256}
```

In the task we get an endpoint which returns random payloads in form:

```
{"nonce": "dcfu+qXOX30=", "ciphertext": "nT0/C209haz3XQs6JcvrEhkbRXnzZiyR87vI82VDvfaQh9eajLNIzkG51TnZg81g7IEPd3UJElZz8xhCMlVb/cXHJO9h", "key": "Fidel_Alejandro_Castro_Ruz_Cuba!"}
```

## Task analysis

The idea is pretty simple -> we need to guess what algorithm was used to encrypt the data, and decrypt the flag.
A classic example of a terrible task design.

## Solution

Knowing cryptography actually not only doesn't help, but also makes this task harder.
We tried lots of different encryptions which match the parameters (like AES-CTR, AES-CCM, AES-GCM etc.), until we finally got a hit with ChaCha20.
And only then we realised that there was a `dance` reference in the task description...

```python
    data = {"nonce": "dcfu+qXOX30=", "ciphertext": "nT0/C209haz3XQs6JcvrEhkbRXnzZiyR87vI82VDvfaQh9eajLNIzkG51TnZg81g7IEPd3UJElZz8xhCMlVb/cXHJO9h",
            "key": "Fidel_Alejandro_Castro_Ruz_Cuba!"}
    nonce = base64.b64decode(data['nonce'])
    ct = base64.b64decode(data['ciphertext'])
    key = data['key']
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ct)
    print(plaintext)
```

And we get `ctf{f38deb0782c0f252090a52b2f1a5b05bf2964272f65d5c3580be631f52f4b3e0}`
