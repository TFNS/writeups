import hashlib
from base64 import b64encode as b64e, b64decode as b64d

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import is_prime

from crypto_commons.netcat.netcat_commons import nc, receive_until, send, receive_until_match


class Rng:
    def __init__(self, seed):
        self.seed = seed
        self.generated = b""
        self.num = 0

    def more_bytes(self):
        self.generated += hashlib.sha256(self.seed).digest()
        self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
        self.num += 256

    def getbits(self, num=64):
        while self.num < num:
            self.more_bytes()
        x = bytes_to_long(self.generated)
        self.num -= num
        self.generated = b""
        if self.num > 0:
            self.generated = long_to_bytes(x >> num, self.num // 8)
        return x & ((1 << num) - 1)


class DiffieHellman:
    def gen_prime(self):
        prime = self.rng.getbits(512)
        iter = 0
        while not is_prime(prime):
            iter += 1
            prime = self.rng.getbits(512)
        return prime

    def __init__(self, seed, prime=None):
        self.rng = Rng(seed)
        if prime is None:
            prime = self.gen_prime()

        self.prime = prime
        self.my_secret = self.rng.getbits()
        self.my_number = pow(5, self.my_secret, prime)
        self.shared = 1337

    def set_other(self, x):
        self.shared ^= pow(x, self.my_secret, self.prime)


def final_round(s, seed):
    receive_until_match(s, "bob number")
    send(s, b64e(b'\x00'))
    receive_until_match(s, "bob number")
    bob_no = int(receive_until(s, "\n").strip())
    alice = DiffieHellman(long_to_bytes(int(seed, 2)))
    alice.set_other(bob_no)
    print('Shared:', alice.shared)
    iv = b64d(receive_until(s, "\n"))
    cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
    enc_flag = b64d(receive_until(s, "\n"))
    print(cipher.decrypt(enc_flag))


def get_iterations(s, msg):
    send(s, b64e(msg))
    receive_until_match(s, "Generated after ")
    count = int(receive_until(s, "\n").split(' ')[0].strip())
    return count


def round(s, suffix=''):
    all_1s = suffix.replace('1', '3').replace('0', '1').replace('3', '0')
    all_1s = '1' + all_1s[:-1] + '0'
    count_all_0s = get_iterations(s, long_to_bytes(int(suffix, 2)))
    count_all_1s = get_iterations(s, long_to_bytes(int(all_1s, 2)))
    print('sub', count_all_1s - count_all_0s)
    if count_all_1s - count_all_0s == 1:
        return '1'
    else:
        return '0'


def main():
    port = 1337
    host = "bitflip1.hackable.software"
    s = nc(host, port)
    print(receive_until(s, "\n"))
    send(s, raw_input(">"))  # PoW
    suffix = '0'
    while len(suffix) < 128:
        print('suffix is', suffix)
        print(receive_until(s, "\n"))
        bit = round(s, suffix=suffix)
        suffix = bit + suffix
    seed = suffix
    print('Seed', seed)
    final_round(s, seed)
    s.close()


if __name__ == '__main__':
    main()
