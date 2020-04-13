import base64

from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime

from crypto_commons.netcat.netcat_commons import nc, receive_until_match, receive_until, send, interactive
from crypto_commons.rsa.rsa_commons import modinv


def recover_n(x, m):
    nn = (x - 1) * modinv(4, m)
    return nn % m


def encrypt(keys, plaintext):
    from Crypto.Cipher import PKCS1_OAEP
    encryptor = PKCS1_OAEP.new(keys)
    return encryptor.encrypt(plaintext)


# def func(bits):
#     keys = gen_rsa_key(bits, e=65537)
#     p = keys.p
#     q = keys.q
#     m = getPrime(bits + 1)
#     x = pow(p, m, m) * pow(q, m, m) + p * pow(q, m, m) + q * pow(p, m, m) + p * q + pow(p, m - 1, m) * pow(q, m - 1, m)
#     text = os.urandom(32)
#     print('Plaintext (b64encoded) : ', b64encode(text).decode())
#     print()
#     print(hex(x)[2:])
#     print(hex(m)[2:])
#     print()
#     ciphertext = input('Ciphertext (b64encoded) : ')
#     check(ciphertext)


def main():
    host = "crypto.byteband.it"
    port = 7002
    s = nc(host, port)
    for i in range(32):
        data = receive_until_match(s, "Plaintext \(b64encoded\) :  ")
        pt = receive_until(s, "\n").decode("base64")
        receive_until(s, "\n")
        x = int(receive_until(s, "\n").strip(), 16)
        m = int(receive_until(s, "\n").strip(), 16)
        print('x', x)
        print('m', m)
        n = recover_n(x, m)
        print('recovered n', n)
        key = RSA.construct((long(n), long(65537)))
        ct = base64.b64encode(encrypt(key, pt))
        print('ct', ct)
        send(s, ct)
    interactive(s)


main()


def sanity():
    bits = 1024
    m = getPrime(bits + 1)
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    x = pow(p, m, m) * pow(q, m, m) + p * pow(q, m, m) + q * pow(p, m, m) + p * q + pow(p, m - 1, m) * pow(q, m - 1, m)
    assert n == (x - 1) / 4


# sanity()
