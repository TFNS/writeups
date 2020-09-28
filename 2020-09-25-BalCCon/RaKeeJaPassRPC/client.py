#!/usr/bin/env python3
import base64
import json
import secrets
import socket
import time
from hashlib import sha256, sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# SRP constants
N = int('d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43', 16)
k = int('b7867f1299da8cc24ab93e08986ebc4d6a478ad0', 16)
g = 2


def encrypt(key, message):
    message = json.dumps(message).encode()
    cipher = AES.new(key, AES.MODE_CBC)
    msg = cipher.encrypt(pad(message, AES.block_size))
    iv = cipher.iv
    hmac = sha1(sha1(key).digest() + msg + iv).digest()
    payload = {
        'message': base64.b64encode(msg).decode(),
        'iv': base64.b64encode(iv).decode(),
        'hmac': base64.b64encode(hmac).decode()
    }
    return payload


def decrypt(key, message):
    iv = base64.b64decode(message['iv'])
    message = base64.b64decode(message['message'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = unpad(cipher.decrypt(message), AES.block_size)
    return json.loads(msg.decode())


if __name__ == '__main__':
    r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    r.settimeout(2)
    r.connect(('pwn.institute', 45269))

    # Calculate A
    a = int(secrets.token_hex(32), 16)
    A = pow(g, a, N)
    while A % N == 0:
        a = int(secrets.token_hex(32), 16)
        A = pow(g, a, N)

    # -----------------------------------------------------------------------
    # IDENTIFY TO SERVER
    # -----------------------------------------------------------------------

    identify_to_server = { 'A': f'{A:X}' }
    payload = json.dumps(identify_to_server)
    r.send(payload.encode())

    # -----------------------------------------------------------------------
    # IDENTIFY TO CLIENT
    # -----------------------------------------------------------------------

    payload = r.recv(1024).decode()
    identify_to_client = json.loads(payload)

    p = input('Token: ')
    B = int(identify_to_client['B'], 16)
    u = int(sha256((f'{A:X}' + identify_to_client['B']).encode()).digest().hex(), 16)
    x = int(sha256((identify_to_client['s'] + p).encode()).digest().hex(), 16)

    kgx = k * pow(g, x, N)
    aux = a + (u * x)
    S = pow(B - kgx, aux, N)

    M = sha256(f'{A:X}{B:X}{S:X}'.encode()).digest().hex()

    # -----------------------------------------------------------------------
    # PROOF TO SERVER
    # -----------------------------------------------------------------------

    proof_to_server = { 'M': M }
    payload = json.dumps(proof_to_server)
    r.send(payload.encode())

    time.sleep(1)

    # -----------------------------------------------------------------------
    # RETRIEVE SECRET
    # -----------------------------------------------------------------------

    payload = {
        "action": "GetSecret"
    }

    key = sha256(f'{S:X}'.encode()).digest()
    payload = json.dumps(encrypt(key, payload))

    r.send(payload.encode())
    payload = r.recv(1024)
    payload = decrypt(key, json.loads(payload))

    print(payload)
    r.close()

