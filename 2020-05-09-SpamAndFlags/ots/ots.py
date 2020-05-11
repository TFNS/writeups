import binascii
import hashlib
import random
import re

from crypto_commons.generic import chunk
from crypto_commons.netcat.netcat_commons import nc, receive_until_match, receive_until, send, interactive


def flip_block(block, original_char, wanted_char):
    missing = ord(original_char) - ord(wanted_char)
    for i in range(missing):
        block = hashlib.md5(block).digest()
    return block


def is_ok(original_hash, new_hash):
    valid_ones = 0
    for a, b in zip(original_hash, new_hash):
        if a >= b:
            valid_ones += 1
    if valid_ones == 15:
        print("Found 15")
    return valid_ones == 16


def calculate_hash(msg):
    raw = msg.encode('utf-8')
    raw = raw + b'\x00' * (128 - 16 - len(raw))
    return hashlib.md5(raw).digest()


def wrap(msg):
    raw = msg.encode('utf-8')
    raw = raw + b'\x00' * (128 - 16 - len(raw))
    raw = raw + hashlib.md5(raw).digest()
    return raw


def flip_hash(msg, original_hash):
    while True:
        nice_msg = msg[:]
        for idx in range(len(nice_msg)):
            if idx in [5, 6, 7, 8]:
                continue
            to = random.randrange(ord(' '), ord(nice_msg[idx]) + 1)
            nice_msg[idx] = chr(to)
        current_msg = "".join(nice_msg)
        current = calculate_hash(current_msg)
        if is_ok(original_hash, current):
            print(current_msg)
            break
    return current_msg


def fix_signature(original_msg, signature, new_msg):
    signature = binascii.unhexlify(signature)
    c = chunk(signature, 16)
    for i in range(len(original_msg)):
        c[i] = flip_block(c[i], original_msg[i], new_msg[i])
    return b''.join(c)


def solve(msg, signature):
    original_msg = msg[:]
    original_hash = calculate_hash(msg)
    msg = list(msg)
    for idx, char in zip([5, 6, 7, 8], 'flag'):
        msg[idx] = char
    new_msg = flip_hash(msg, original_hash)
    new_sig = fix_signature(wrap(original_msg), signature, wrap(new_msg))
    return new_msg, binascii.hexlify(new_sig)


def main():
    port = 1337
    host = "34.89.64.81"
    s = nc(host, port)
    skip = receive_until_match(s, "pub_key = ")
    skip = receive_until_match(s, "pub_key = ")
    skip = receive_until_match(s, "pub_key = ")
    pubkey = receive_until(s, b"\n")[:-1]
    msg = receive_until(s, b"=")
    msg = re.findall("\"(.*)\"", msg.decode("utf-8"))[0]
    sig = receive_until(s, b"\n")[1:-1]
    print(pubkey)
    print(msg)
    print(sig)
    m, sig = solve(msg, sig)
    send(s, m.encode("utf-8"))
    send(s, sig.encode("utf-8"))
    interactive(s)


main()
