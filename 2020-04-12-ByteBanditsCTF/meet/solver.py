import string
import sys
from string import printable

from Crypto.Cipher import AES


def first_half():
    pt = 'aaaaaaaaaaaaaaaa'
    val = len(pt) % 16
    if not val == 0:
        pt += '0' * (16 - val)
    res = {}
    for a in printable:
        for b in printable:
            for c in printable:
                key1 = '0' * 13 + a + b + c
                cipher1 = AES.new(key=key1, mode=AES.MODE_ECB)
                c1 = cipher1.encrypt(pt.encode('hex')).encode("hex")
                res[c1] = key1
    return res


def second_half(first_half):
    ct = "ef92fab38516aa95fdc53c2eb7e8fe1d5e12288fdc9d026e30469f38ca87c305ef92fab38516aa95fdc53c2eb7e8fe1d5e12288fdc9d026e30469f38ca87c305".decode("hex")
    for a in printable:
        for b in printable:
            for c in printable:
                key2 = a + b + c + '0' * 13
                cipher2 = AES.new(key=key2, mode=AES.MODE_ECB)
                res = cipher2.decrypt(ct)
                if res in first_half:
                    key1 = first_half[res]
                    return key1, key2


def main():
    flag = 'fa364f11360cef2550bd9426948af22919f8bdf4903ee561ba3d9b9c7daba4e759268b5b5b4ea2589af3cf4abe6f9ae7e33c84e73a9c1630a25752ad2a984abfbbfaca24f7c0b4313e87e396f2bf5ae56ee99bb03c2ffdf67072e1dc98f9ef691db700d73f85f57ebd84f5c1711a28d1a50787d6e1b5e726bc50db5a3694f576'.decode(
        "hex")
    first = first_half()
    print("first complete")
    key1, key2 = second_half(first)
    cipher1 = AES.new(key=key1, mode=AES.MODE_ECB)
    cipher2 = AES.new(key=key2, mode=AES.MODE_ECB)
    print(key1, key2)
    print(cipher1.decrypt(cipher2.decrypt(flag).decode("hex")).decode("hex"))


main()


def unintended():
    flag = 'fa364f11360cef2550bd9426948af22919f8bdf4903ee561ba3d9b9c7daba4e759268b5b5b4ea2589af3cf4abe6f9ae7e33c84e73a9c1630a25752ad2a984abfbbfaca24f7c0b4313e87e396f2bf5ae56ee99bb03c2ffdf67072e1dc98f9ef691db700d73f85f57ebd84f5c1711a28d1a50787d6e1b5e726bc50db5a3694f576'.decode(
        "hex")
    for a in printable:
        for b in printable:
            for c in printable:
                key2 = a + b + c + '0' * 13
                cipher2 = AES.new(key=key2, mode=AES.MODE_ECB)
                x = cipher2.decrypt(flag)
                if len(set(x).difference(string.hexdigits)) == 0:
                    print("Found second", key2)
                    for a in printable:
                        for b in printable:
                            for c in printable:
                                key1 = '0' * 13 + a + b + c
                                cipher1 = AES.new(key=key1, mode=AES.MODE_ECB)
                                y = cipher1.decrypt(x.decode("hex"))
                                if len(set(y).difference(string.hexdigits)) == 0:
                                    print("Found first", key1)
                                    print(y.decode("hex"))
                                    sys.exit(0)

# unintended()
