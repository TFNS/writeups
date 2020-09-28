#!/usr/bin/python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from base64 import b64encode, b64decode
from sys import argv
from os import urandom

from flag import FLAG

def get_server_privatekey(pin: str) -> x25519.X25519PrivateKey:
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(pin.encode())
    privatekey_bytes = digest.finalize()
    return x25519.X25519PrivateKey.from_private_bytes(privatekey_bytes)

def get_peer_publickey(key: str) -> x25519.X25519PublicKey:
    try:
        key_bytes = b64decode(key)
        if(len(key_bytes) != 32):
            return None
        key = x25519.X25519PublicKey.from_public_bytes(key_bytes)
        return key
    except:
        return None

def encode_publickey(key: x25519.X25519PrivateKey) -> str:
    return b64encode(key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)).decode("ascii")

def communicate():
    peer_publickey_encoded = input("Please enter your identity key: ")
    if(not (peer_publickey_encoded in friends or peer_publickey_encoded in best_friends)):
        print("I do not know you.")
        exit(-1)
    peer_publickey = get_peer_publickey(peer_publickey_encoded)
    if(not peer_publickey):
        print("Bad key")
        exit(-1)

    # Do key agreement
    # Authenticate the peer with the identity keys to prevent Man-in-the-middle
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

    # Do a challenge/response authentication with the peer
    challenge = urandom(16)
    print("Proof that you really know your private keys. Here is your challenge: {}".format(b64encode(challenge).decode("ascii")))
    response = input("What is your response? ")
    mac = hmac.HMAC(sharedkey, hashes.SHA3_256(), backend=default_backend())
    mac.update(challenge)
    expected_response = b64encode(mac.finalize()).decode("ascii")
    if(response != expected_response):
        print("This is not the response I was looking for")
        exit(-1)

    # We are really talking to a friend
    if(peer_publickey_encoded in best_friends):
        print("Hello BFF. Here is your flag: {}".format(FLAG))
        exit(0)
    else:
        print("Well done, friend. Now sod off.")


friends = []
best_friends = ["SgZSsPzLpfoEqnJojn+lftJekF7Q0yKYqcGSAOL2cyM="]

if len(argv) != 2:
    print("Illegal execution of script")
    exit(-1)

private_key = get_server_privatekey(argv[1])
publickey_encoded = encode_publickey(private_key)

print("Hello!!!")
print("This is the secret server of the friendship society dedicated to the actress Katherine Ceta-Iones.")
print("Let me introduce myself. My identity key is {}.".format(publickey_encoded))
print("You need to become a friend to talk to us.")
print("But please note, that the best secrets will only by shared with the best friends.")
print("\n===========================================\n")

while True:
    selection = input("Do you want to become a friend of the society (1) or start a communication (2)? ")

    if(selection == '1'):
        peer_key = input("Please enter your identity key (32 bytes, BASE64 encoded): ")
        if(peer_key in friends):
            print("You already are a friend.")
            exit(-1)
        if(get_peer_publickey(peer_key)):
            friends.append(peer_key)
            print("Welcome, friend!")
        else:
            print("Bad key.")
            exit(-1)
    elif(selection == '2'):
        print("OK, lets talk.")
        communicate()
    else:
        print("Bad choice.")
        exit(-1)
