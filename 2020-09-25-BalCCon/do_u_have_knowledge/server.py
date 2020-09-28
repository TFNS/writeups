import time
from base64 import b64encode
import random
from os import urandom
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AnsiRng:

    _state = None

    def _get_timestamp (self) -> bytes :
        unix_ts = int(time.time() * 1000000)
        return int.to_bytes(unix_ts, length=16, byteorder='little')

    def __init__ (self, seed: bytes):
        if(not seed or len(seed) != 16):
            raise Error('Seed must be 16 bytes long')
        self._state = seed

    def _get_random_block(self):
        t = self._get_timestamp()
        cipher = Cipher(algorithms.AES(b'1234567890123456'), modes.ECB(), backend = default_backend())
        c1 = cipher.encryptor().update(t)
        c2 = bytes([c1[i] ^ self._state[i] for i in range(16)])
        o = cipher.encryptor().update(c2)
        c3 = bytes([c1[i] ^ o[i] for i in range(16)])
        self._state = cipher.encryptor().update(c3)
        return o
        
    def get_random(self, length=16):
        o = b''
        for i in range(int(length/16)):
            o = o + self._get_random_block()
        return o[:length]

def play_lottery() -> bool:
    random.seed(int(time.time()))
    for _ in range(3):
        number = random.randint(1,65535)
        guess = input('Guess the next lottery number: ')
        guess = int(guess)
        if(number == guess):
            print('Congratulations, you won the lottery.')
            return True
        else:
            print('Wrong. The correct number was {}.'.format(number))
    return False

print(time.ctime())
# Let's play the lottery
try:
    if(not play_lottery()):
        print('Better luck next time')
        exit(-1)
except:
    print('Fair play, please.')
    exit(-1)
# Give the player an encrypted flag as the prize
with open('flag.txt') as f: flag = f.read()
# Use a cryptographically secure random number generator to secure the flag
rng = AnsiRng(urandom(16)) # Use an unguessable seed value for the RNG
key = rng.get_random(16)
r = rng.get_random(32)
nonce = r[:12]
ad = r[12:]

cipher = AESCCM(key, tag_length=16)
encrypted_flag = cipher.encrypt(nonce, flag.encode('utf-8'), associated_data=ad)
output = b64encode(nonce + ad + encrypted_flag).decode('utf-8')
print("Here is your encrypted flag: {}".format(output))
exit(0)
