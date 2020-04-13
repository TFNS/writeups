from crypto_commons.brute.brute import brute

mod = int(1e9 + 7)
mod2 = int(1e9 + 9)

pows1 = [pow(31, i, mod) for i in range(105)]
pows2 = [pow(31, i, mod2) for i in range(105)]


def func1s(s):
    h = 0
    for i in range(len(s)):
        h += (ord(s[i]) - 96) * pow(31, i, mod)
        h %= mod
    return h


def func2s(s):
    h = 0
    for i in range(len(s)):
        h += (ord(s[i]) - 96) * pow(31, i, mod2)
        h %= mod2
    return h


def func1(s):
    h = 0
    for i in range(len(s)):
        h += (ord(s[i]) - 96) * pows1[i]
        h %= mod
    return h


def func2(s):
    h = 0
    for i in range(len(s)):
        h += (ord(s[i]) - 96) * pows2[i]
        h %= mod2
    return h


def worker(x):
    print(x)
    file_data = open("a/" + str(x)).read()
    memorized_hashes = {}
    for a in range(1, 1001):
        for b in range(a - 1, a + 101):
            s1 = file_data[a - 1: b]
            ha1 = func1(s1)
            ha2 = func2(s1)
            h = str(ha1) + " " + str(ha2)
            memorized_hashes[h] = s1
    return memorized_hashes


def main_d():
    maps = brute(worker, range(20), processes=6)
    memorized_hashes = {}
    for m in maps:
        memorized_hashes.update(m)
    expected_hashes = open("hashes.txt", 'r').readlines()
    s = ""
    for h in expected_hashes:
        s1 = memorized_hashes[h.strip()]
        s += s1
    hsh1 = func1s(s)
    hsh2 = func2s(s)
    print(hsh1, hsh2)
    print('flag{%d}' % (hsh1 * hsh2))


if __name__ == '__main__':
    main_d()
