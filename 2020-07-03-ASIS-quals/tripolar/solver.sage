from hashlib import sha1

def crow(x, y, z):
    res = x ** 3 + 3 * (x + 2) * y ** 2 + y ** 3 + 3 * (x + y + 1) * z ** 2 + z ** 3 + 6 * x ** 2 + (3 * x ** 2 + 12 * x + 5) * y + \
          (3 * x ** 2 + 6 * (x + 1) * y + 3 * y ** 2 + 6 * x + 2) * z + 11 * x
    return int(res // 6)

def keygen(nbit):
    p, q, r = [random_prime(2**nbit) for _ in range(3)]
    pk = crow(p, q, r)
    return p, q, r, pk


def encrypt(msg, key):
    p, q, r, pk = key
    _msg = int(bytes_to_long(msg))
    assert _msg < p * q * r
    _hash = int(bytes_to_long(sha1(msg).digest()))
    _enc = int(pow(_msg, 31337, p * q * r))
    res = int(crow(_enc * pk, pk * _hash, _hash * _enc))
    return res


def solve(enc, mode=2, gcd_bit_bound=700):
    S = ZZ(enc * 6).nth_root(3,truncate_mode=1)[0] - 1
    r1 = 6 * enc - (S) ** 3
    r2 = 6 * S ** 2 - r1
    L = r2 + 5 * S
    RR = RealField(2000)
    R.<v> = PolynomialRing(RR)
    pol = (3*v**2)/(2*S+1) - 3 * v + L/(2*S+1) +2
    for approx_z, _ in pol.roots():
        approx_z = int(approx_z)
        for c in range(-50, 50):
            cand_z = approx_z + c
            cand_x = int((3 * cand_z * (2 * S + 1) - 3 * cand_z ** 2 - r2 - 5 * S) // 6)
            cand_y = S - cand_z - cand_x
            enc = gcd(cand_x, cand_y)
            if mode == 1 and len(bin(enc)) > gcd_bit_bound or mode == 2 and is_prime(cand_x) and is_prime(cand_y) and is_prime(cand_z): 
                return cand_x, cand_y, cand_z

def bytes_to_long(data):
    return int(data.encode('hex'), 16)

def long_to_bytes(data):
    return hex(int(data)).replace("0x","").replace("L","").decode("hex")

def main():
    res = 2149746514930580893244331421788929339625440444035620415342330419606266919679366683714353190036245926925599992281979981146349624735527272311371385020589871836913619378311391262773292002172286277050453912686346788369011436136749187588094689078604688584902911179760648455086471764073748888909794220109293997848416687601544131530407244078221642967646447253616998155897027002613854305998810584288668106945154515431677901508248501719233358613388284911544653423679952387626753952473637341066170188791146059852636168715040552123771116865138447219250612402255341219117297714079726770332109952708459351802562275694535824071439914386289373243983185946795491819129870207658214310478641067801668872244606421878692919649372294669971163490263922400626336242549835706388683877132951576008701491480511964700265393284833130226932921133394423802845820376416051352258291552872659169273062675846495338968217135950455977401551939531925192805141513749352229791333923735208796396811016155462890934792375784262889437336581789661289949141905602572787198543216492782644044690961535388836272756550843545526602092242838754566866668770935315676090418730740458031516514972175558292490434340653602286960865392593256844629420033899513449695339367156173095463513078538974962886381545956586331314243000178758164274052565937247768118311842079769519252368952306761435644300926556436608921187592529049031682872480807213750
    x,y,z = solve(res, 1)
    _enc = int(gcd(x, z))
    _hash = int(z // _enc)
    pk = int(y // _hash)
    assert x == _enc  * pk
    assert y == _hash * pk
    assert z == _enc  * _hash
    p, q, r = solve(pk)
    phi = (p - 1) * (q - 1) * (r - 1)
    d = inverse_mod(31337, phi)
    print(long_to_bytes(pow(_enc, d, p * q * r)))

main()

def sanity():
    key = keygen(256)
    p, q, r, pk = key
    S = ZZ(pk * 6).nth_root(3,truncate_mode=1)[0] - 1
    assert S == (p + q + r)
    r1 = 6 * pk - (p + q + r) ** 3
    r2 = 6 * S ** 2 - r1
    x, y, z = p, q, r
    assert r2 == -(6 * (2 * x + y + z) - 6 * (x * z + y * z) - (x + y + 4 * z + 3 * z ** 2))
    assert r2 == 6 * (x * z + y * z) + (x + y + 4 * z + 3 * z ** 2) - 6 * (2 * x + y + z)
    assert r2 == 6 * (x * z + y * z) + (S + 3 * z + 3 * z ** 2) - 6 * (x + S)
    assert r2 == 6 * x * z + 6 * y * z + S + 3 * z + 3 * z ** 2 - 6 * x + -6 * S
    assert r2 == 6 * x * z + 6 * y * z + 3 * z + 3 * z ** 2 - 6 * x - 5 * S
    assert r2 + 5 * S == 6 * x * z + 6 * y * z + 3 * z + 3 * z ** 2 - 6 * x
    L = r2 + 5 * S
    assert L == z * (6 * y + 6 * x + 3 * z + 3) - 6 * x
    assert L == 3*z*(2*S+1) -3*z**2 - 6*x
    assert L/(2*S+1) == 3*z -3/(2*S+1)*z**2 - 6*x/(2*S+1)
    assert 3/(2*S+1)*z**2 - 3*z + L/(2*S+1) + 6*x/(2*S+1) == 0
    cand_x, cand_y, cand_z = solve(pk)
    assert z == cand_z
    assert x == cand_x
    assert y == cand_y


#sanity()
