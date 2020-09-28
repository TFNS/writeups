#!/usr/bin/env python3
import base64
import json
import secrets
import socketserver
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
    msg = base64.b64decode(message['message'])
    iv = base64.b64decode(message['iv'])
    hmac = sha1(sha1(key).digest() + msg + iv).digest()
    if hmac != base64.b64decode(message['hmac']):
        return None
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = unpad(cipher.decrypt(msg), AES.block_size)
    return json.loads(msg.decode())


class SRPHandler(socketserver.StreamRequestHandler):
    timeout = 2

    def handle(self):
        # -----------------------------------------------------------------------
        # IDENTIFY TO SERVER
        # -----------------------------------------------------------------------

        payload = self.request.recv(1024).decode()
        payload = json.loads(payload)

        A = int(payload['A'], 16)

        # Generate password for administrator and log for side-channel SRP
        p = secrets.token_hex(32)
        print(p)

        # Generate session key
        s = secrets.token_hex(32)
        x = int(sha256((s + p).encode()).digest().hex(), 16)
        v = pow(g, x, N)

        # Calculate B
        b = int(secrets.token_hex(32), 16)
        B = (k * v) + pow(g, b, N)
        while B % N == 0:
            b = int(secrets.token_hex(32), 16)
            B = (k * v) + pow(g, b, N)


        # -----------------------------------------------------------------------
        # IDENTIFY TO CLIENT
        # -----------------------------------------------------------------------

        identify_to_client = { 's': s, 'B': f'{B:X}' }
        payload = json.dumps(identify_to_client)
        self.request.send(payload.encode())

        u = int(sha256(f'{A:X}{B:X}'.encode()).digest().hex(), 16)
        if u == 0:
            return

        S = pow(A * pow(v, u, N), b, N)
        M = sha256(f'{A:X}{B:X}{S:X}'.encode()).digest().hex()

        # -----------------------------------------------------------------------
        # PROOF TO SERVER
        # -----------------------------------------------------------------------

        payload = self.request.recv(1024).decode()
        payload = json.loads(payload)
        if payload['M'] != M:
            return

        # -----------------------------------------------------------------------
        # RETREVE SECRET
        # -----------------------------------------------------------------------

        payload = self.request.recv(1024).decode()
        key = sha256(f'{S:X}'.encode()).digest()
        payload = decrypt(key, json.loads(payload))
        if payload is None:
            return

        if payload['action'] == 'GetSecret':
            with open('flag.txt') as f:
                payload = json.dumps(encrypt(key, json.dumps({ 'flag': f.read() })))
                self.request.send(payload.encode())


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(('0.0.0.0', 31337), SRPHandler) as server:
        server.serve_forever()

