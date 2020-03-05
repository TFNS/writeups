#!/usr/bin/env python3.7

import numpy as np

from itertools import chain


class Cipher(object):
    def __init__(self, key: int, canary: int):
        self._key = key
        self._canary = canary
        return

    @property
    def canary(self) -> int:
        return self._canary

    def encrypt(self, message: bytes) -> bytes:
        plaintext = int.from_bytes(message, 'big')
        assert self._key.bit_length() >= plaintext.bit_length()
        ciphertext = self._key ^ plaintext
        length = (ciphertext.bit_length() + 7) // 8
        return ciphertext.to_bytes(length, 'big')

    def decrypt(self, message: bytes) -> bytes:
        raise NotImplementedError

    @classmethod
    def create(cls, source: np.ndarray) -> 'Cipher':
        assert len(set(source.shape)) == 1
        line = source.reshape(-1)
        assert len(line) == len(set(line) & set(range(len(line))))
        keys = set(map(sum, chain.from_iterable((*s, np.diag(s)) for s in [source, source.T])))
        assert len(keys) == 1
        key = int(keys.pop())
        return cls(key, key % len(line))
    

def main():
    from secret import SECRET, FLAG
    cipher = Cipher.create(SECRET)
    print(cipher.encrypt(FLAG).hex())
    print(cipher.canary)
    return


if __name__ == '__main__':
    main()
