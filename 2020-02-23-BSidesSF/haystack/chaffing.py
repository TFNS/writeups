import binascii
import hashlib
import hmac
import random
import struct
from collections import Counter

CHAFF_SIZE = 32
SIG_SIZE = 16
ALL_BYTES = set((c for c in range(256)))
KEY = binascii.unhexlify('af5f76f605a700ae8c0895c3e6175909')
KEY = b'af5f76f605a700ae8c0895c3e6175909'


def byte(v):
    return bytes([v])


def sign_byte(val, key):
    return hmac.new(key, val, digestmod=hashlib.sha256).digest()[:SIG_SIZE]


def chaff_byte(val, key):
    msgs = {}
    msgs[val[0]] = sign_byte(val, key)
    while len(msgs) < CHAFF_SIZE:
        vals = list(ALL_BYTES - set(msgs.keys()))
        c = random.choice(vals)
        if c == val:
            raise ValueError('Chose duplicate!')
        fake_sig = bytes(random.choices((list(ALL_BYTES)), k=SIG_SIZE))
        msgs[c] = fake_sig

    pieces = []
    for k, v in msgs.items():
        pieces.append(b'%s%s' % (byte(k), v))

    random.shuffle(pieces)
    return b''.join(pieces)


def chaff_msg(val, key):
    if not isinstance(val, bytes):
        val = val.encode('utf-8')
    msg_out = []
    for b in val:
        msg_out.append(chaff_byte(byte(b), key))

    outval = b''.join(msg_out)
    return struct.pack('>I', len(val)) + outval


def winnow_msg(val, key):
    if not isinstance(val, bytes):
        val = val.encode('utf-8')
    msglen = struct.unpack('>I', val[:4])[0]
    val = val[4:]
    chunk_len = (SIG_SIZE + 1) * CHAFF_SIZE
    expected_len = chunk_len * msglen
    if len(val) != expected_len:
        raise ValueError('Expected length %d, saw %d.' % (expected_len, len(val)))
    pieces = []
    for c in range(msglen):
        chunk = val[chunk_len * c:chunk_len * (c + 1)]
        res = winnow_byte(chunk, key)
        pieces.append(res)

    return b''.join(pieces)


def winnow_byte(val, key):
    while val:
        c = byte(val[0])
        sig = val[1:SIG_SIZE + 1]
        if sign_byte(c, key) == sig:
            return c
        val = val[SIG_SIZE + 1:]
    raise ValueError('No valid sig found!')


def original_main():
    inp = b'This is a test message!'
    msg = chaff_msg(inp, KEY)
    ret = winnow_msg(msg, KEY)
    if inp != ret:
        print('Wrong ret: %s' % ret)