from fglg import FiniteGeneralLinearGroup
from secret import flag
import base64
import math

def menu():
    print("====================")
    print("[1] Encrypt", flush=True)
    print("[2] Decrypt", flush=True)
    print("====================")
    try:
        print("> ", end="", flush=True)
        return int(input())
    except:
        return 0

def bytes2gl(b, n, p=None):
    assert len(b) <= n * n
    X = FiniteGeneralLinearGroup(n, p)
    padlen = n * n - len(b)
    b = bytes([padlen]) * padlen + b
    for i in range(n):
        for j in range(n):
            X.set_at((j, i), b[i*n + j])
    return X

def recv_message(n, p):
    print("Data: ", end="", flush=True)
    b = base64.b64decode(input())
    return bytes2gl(b, n, p)

def encrypt(U, X):
    return U * X * U**-1

def decrypt(U, X):
    return U**-1 * X * U

if __name__ == '__main__':
    # Create flag F
    n = math.ceil(math.sqrt(len(flag)))
    F = bytes2gl(flag, n)
    p = F.p
    
    # Generate private key
    U = FiniteGeneralLinearGroup(n, p)
    while U.determinant() == 0:
        U.set_random()

    eF = encrypt(U, F)
    assert decrypt(U, eF) == F
    print("Encrypted Flag:", flush=True)
    print(eF, flush=True)
    print("p = {}".format(F.p), flush=True)

    while True:
        choice = menu()
        if choice == 1:
            # Encrypt
            M = recv_message(U.n, U.p)
            C = encrypt(U, M)
            print("Encrypted:", flush=True)
            print(C, flush=True)
        elif choice == 2:
            # Decrypt
            C = recv_message(U.n, U.p)
            M = decrypt(U, C)
            print("Decrypted:", flush=True)
            print(M, flush=True)
        else:
            break

    print("Bye!", flush=True)
