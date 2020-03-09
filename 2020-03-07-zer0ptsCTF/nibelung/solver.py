import base64
import re

from crypto_commons.netcat.netcat_commons import nc, receive_until, send
from fglg import FiniteGeneralLinearGroup


def bytes2gl(b, n, p=None):
    assert len(b) <= n * n
    X = FiniteGeneralLinearGroup(n, p)
    padlen = n * n - len(b)
    b = chr(padlen) * padlen + b
    b = map(ord, b)
    for i in range(n):
        for j in range(n):
            X.set_at((j, i), b[i * n + j])
    return X


def encrypt(U, X):
    return U * X * U ** -1


def decrypt(U, X):
    return U ** -1 * X * U


def create_from_matrix(matrix, n, p):
    res = FiniteGeneralLinearGroup(n, p)
    for i in range(n):
        for j in range(n):
            res.set_at((j, i), matrix[i][j])
    return res


def parse_stringified(response):
    rows = re.findall("(\[\d+.*?\])", response)
    return [eval(row) for row in rows]


def solver(res, p, dec_oracle):
    n = len(res)
    recovered = FiniteGeneralLinearGroup(n, p)
    for i in range(n):
        for j in range(n):
            print('recovered', i, j)
            val = res[i][j]
            k = val / 255
            remainder = val % 255
            payload = list('\0' * n * n)
            payload[i * n + j] = chr(255)
            result_255 = dec_oracle("".join(payload))
            X = create_from_matrix(result_255, n, p)
            recovered += X * k
            payload[i * n + j] = chr(remainder)
            result_remainder = dec_oracle("".join(payload))
            X = create_from_matrix(result_remainder, n, p)
            recovered += X
    return recovered


def real_oracle(s, payload):
    send(s, "2")
    x = receive_until(s, ":")
    send(s, base64.b64encode(payload))
    x = receive_until(s, "\n")
    result = receive_until(s, "=")
    response_matrix = parse_stringified(result[:-1])
    x = receive_until(s, ">")
    return response_matrix


def main():
    host = "13.231.224.102"
    port = 3002
    s = nc(host, port)
    x = receive_until(s, "\n")
    encflag = receive_until(s, "p")
    encflag_matrix = parse_stringified(encflag[:-1])
    p = int(receive_until(s, "\n")[2:])
    x = receive_until(s, ">")
    result = solver(encflag_matrix, p, lambda payload: real_oracle(s, payload))
    flag = parse_stringified(str(result))
    print("".join(["".join(map(chr, a)) for a in flag]))


main()


def test_dec_oracle(U, n, p, payload):
    F = bytes2gl(payload, n, p)
    return parse_stringified(str(decrypt(U, F)))


def sanity():
    n = 2
    F = bytes2gl("A\0\0\0", n)
    print(F)
    p = F.p
    print(p)
    U = FiniteGeneralLinearGroup(n, p)
    while U.determinant() == 0:
        U.set_random()
    res = encrypt(U, F)
    result = solver(parse_stringified(str(res)), p, lambda payload: test_dec_oracle(U, n, p, payload))
    print(result)


# sanity()


def sanity2():
    n = 2
    F = bytes2gl("\0" * (n * n), n)
    p = F.p
    res = """
[[65, 66]
 [67, 68]]"""
    x = parse_stringified(res)
    print(create_from_matrix(x, n, p))


# sanity2()

def sanity3():
    n = 2
    F = bytes2gl("ABCD", n)
    print(F)
    p = F.p
    print(p)
    U = FiniteGeneralLinearGroup(n, p)
    while U.determinant() == 0:
        U.set_random()
    res = encrypt(U, F)

    print(decrypt(U, res))
    print(solver(parse_stringified(str(res)), p, lambda payload: test_dec_oracle(U, n, p, payload)))

    divisor = 255
    mod = 255
    v = 255

    result = FiniteGeneralLinearGroup(n, p)
    val = res.get_at((0, 0))
    k = val / divisor
    print(k)
    remainder = val % mod
    F = bytes2gl(chr(v) + "\0\0\0", n, p)
    r1 = decrypt(U, F)
    result += r1 * k
    F = bytes2gl(chr(remainder) + "\0\0\0", n, p)
    r1 = decrypt(U, F)
    result += r1

    val = res.get_at((1, 0))
    k = val / divisor
    print(k)
    remainder = val % mod
    F = bytes2gl('\0' + chr(v) + "\0\0", n, p)
    r2 = decrypt(U, F)
    result += r2 * k
    F = bytes2gl('\0' + chr(remainder) + "\0\0", n, p)
    r2 = decrypt(U, F)
    result += r2

    val = res.get_at((0, 1))
    k = val / divisor
    print(k)
    remainder = val % mod
    F = bytes2gl('\0\0' + chr(v) + "\0", n, p)
    r3 = decrypt(U, F)
    result += r3 * k
    F = bytes2gl('\0\0' + chr(remainder) + "\0", n, p)
    r3 = decrypt(U, F)
    result += r3

    val = res.get_at((1, 1))
    k = val / divisor
    print(k)
    remainder = val % mod
    F = bytes2gl('\0\0\0' + chr(v), n, p)
    r4 = decrypt(U, F)
    result += r4 * k
    F = bytes2gl('\0\0\0' + chr(remainder), n, p)
    r4 = decrypt(U, F)
    result += r4

    print(result)


# sanity3()


def sanity4():
    n = 2
    U = FiniteGeneralLinearGroup(n, bits=8)
    while U.determinant() == 0:
        U.set_random()
    p = U.p
    print(p)
    F = bytes2gl("A\0\0\0", n)
    print(F)
    res = encrypt(U, F)
    print(res)

    print(decrypt(U, res))

    F = bytes2gl(chr(res.get_at((0, 0))) + "\0\0\0", n, p)
    r1 = decrypt(U, F)
    F = bytes2gl('\0' + chr(res.get_at((1, 0))) + "\0\0", n, p)
    r2 = decrypt(U, F)
    F = bytes2gl('\0\0' + chr(res.get_at((0, 1))) + '\0', n, p)
    r3 = decrypt(U, F)
    F = bytes2gl('\0\0\0' + chr(res.get_at((1, 1))), n, p)
    r4 = decrypt(U, F)
    print(r1 + r2 + r3 + r4)


# sanity4()
