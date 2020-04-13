mod = int(1e9 + 7)
mod2 = int(1e9 + 9)
import random

f = open("hashes.txt", "w")


def func1(s):
    h = 0
    for i in range(len(s)):
        h += (ord(s[i]) - 96) * pow(31, i, mod)
        h %= mod
    return h


def func2(s):
    h = 0
    for i in range(len(s)):
        h += (ord(s[i]) - 96) * pow(31, i, mod2)
        h %= mod2
    return h


saa = ""


def main():
    i = 0
    s = ""
    a1 = ""
    d = {}
    while i < 10000:
        x = random.randint(0, 19)
        a = random.randint(1, 1000)
        b = random.randint(a, a + 100)
        s1 = open("a/" + str(x)).read()[a - 1 : b]
        ha1 = func1(s1)
        ha2 = func2(s1)
        if d.get((ha1, ha2)) is not None:
            continue
        s += s1
        i += 1
        d[(ha1, ha2)] = 1
        a1 += str(ha1) + " " + str(ha2) + "\n"
    f.write(a1)
    f.close()
    # hsh1 = func1(s)
    # hsh2 = func2(s)
    # print(hsh1, hsh2)


if __name__ == "__main__":
    main()
