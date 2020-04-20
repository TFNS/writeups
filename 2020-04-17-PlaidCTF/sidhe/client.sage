import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import sys
import re
import socket
import telnetlib
import itertools
import string

# SIDH parameters from SIKEp434
# using built-in weierstrass curves instead of montgomery curves because i'm lazy
e2 = 0xD8
e3 = 0x89
p = (2^e2)*(3^e3)-1
K.<ii> = GF(p^2, modulus=x^2+1)
E = EllipticCurve(K, [0,6,0,1,0])
xP20 = 0x00003CCFC5E1F050030363E6920A0F7A4C6C71E63DE63A0E6475AF621995705F7C84500CB2BB61E950E19EAB8661D25C4A50ED279646CB48
xP21 = 0x0001AD1C1CAE7840EDDA6D8A924520F60E573D3B9DFAC6D189941CB22326D284A8816CC4249410FE80D68047D823C97D705246F869E3EA50
yP20 = 0x0001AB066B84949582E3F66688452B9255E72A017C45B148D719D9A63CDB7BE6F48C812E33B68161D5AB3A0A36906F04A6A6957E6F4FB2E0
yP21 = 0x0000FD87F67EA576CE97FF65BF9F4F7688C4C752DCE9F8BD2B36AD66E04249AAF8337C01E6E4E1A844267BA1A1887B433729E1DD90C7DD2F
xQ20 = 0x0000C7461738340EFCF09CE388F666EB38F7F3AFD42DC0B664D9F461F31AA2EDC6B4AB71BD42F4D7C058E13F64B237EF7DDD2ABC0DEB0C6C
xQ21 = 0x000025DE37157F50D75D320DD0682AB4A67E471586FBC2D31AA32E6957FA2B2614C4CD40A1E27283EAAF4272AE517847197432E2D61C85F5
yQ20 = 0x0001D407B70B01E4AEE172EDF491F4EF32144F03F5E054CEF9FDE5A35EFA3642A11817905ED0D4F193F31124264924A5F64EFE14B6EC97E5
yQ21 = 0x0000E7DEC8C32F50A4E735A839DCDB89FE0763A184C525F7B7D0EBC0E84E9D83E9AC53A572A25D19E1464B509D97272AE761657B4765B3D6
xP30 = 0x00008664865EA7D816F03B31E223C26D406A2C6CD0C3D667466056AAE85895EC37368BFC009DFAFCB3D97E639F65E9E45F46573B0637B7A9
xP31 = 0x00000000
yP30 = 0x00006AE515593E73976091978DFBD70BDA0DD6BCAEEBFDD4FB1E748DDD9ED3FDCF679726C67A3B2CC12B39805B32B612E058A4280764443B
yP31 = 0x00000000
xQ30 = 0x00012E84D7652558E694BF84C1FBDAAF99B83B4266C32EC65B10457BCAF94C63EB063681E8B1E7398C0B241C19B9665FDB9E1406DA3D3846
xQ31 = 0x00000000
yQ30 = 0x00000000
yQ31 = 0x0000EBAAA6C731271673BEECE467FD5ED9CC29AB564BDED7BDEAA86DD1E0FDDF399EDCC9B49C829EF53C7D7A35C3A0745D73C424FB4A5FD2
P2 = E(xP20+ii*xP21, yP20+ii*yP21)
Q2 = E(xQ20+ii*xQ21, yQ20+ii*yQ21)
P3 = E(xP30+ii*xP31, yP30+ii*yP31)
Q3 = E(xQ30+ii*xQ31, yQ30+ii*yQ31)

def nc(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def receive_until(s, delimiters, break_on_empty=False):
    all_data = ""
    data = s.recv(1)
    while data not in delimiters:
        all_data += data
        data = s.recv(1)
        if data == '' and break_on_empty:
            return all_data
    return all_data + data

def send(s, payload):
    s.sendall(payload + b"\n")


def interactive(s):
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()


def elem_to_coefficients(x):
    l = x.polynomial().list()
    l += [0]*(2-len(l))
    return l

def elem_to_bytes(x):
    n = ceil(log(p,2)/8)
    x0,x1 = elem_to_coefficients(x) # x == x0 + ii*x1
    x0 = ZZ(x0).digits(256, padto=n)
    x1 = ZZ(x1).digits(256, padto=n)
    return "".join(map(long_to_bytes,(x0+x1))) # stupid py3

def isogen2(sk2):
    Ei = E
    P = P3
    Q = Q3
    S = P2+sk2*Q2
    for i in range(e2):
        phi = Ei.isogeny((2^(e2-i-1))*S)
        Ei = phi.codomain()
        S = phi(S)
        P = phi(P)
        Q = phi(Q)
    return (Ei,P,Q)

def isoex2(sk2, pk3):
    Ei, P, Q = pk3
    S = P+sk2*Q
    for i in range(e2):
        R = (2^(e2-i-1))*S
        phi = Ei.isogeny(R)
        Ei = phi.codomain()
        S = phi(S)
    return Ei.j_invariant()

def parse_K_elem(re,im):
    re = ZZ(re)
    im = ZZ(im)
    return K(re + ii*im)

supersingular_cache = set()
def is_supersingular(Ei):
    a = Ei.a_invariants()
    if a in supersingular_cache:
        return True
    result = Ei.is_supersingular(proof=False)
    if result:
        supersingular_cache.add(a)
    return result

def send_key(s, pk2):
    send(s,str(elem_to_coefficients(pk2[0].a1())[0]))
    send(s,str(elem_to_coefficients(pk2[0].a1())[1]))
    send(s,str(elem_to_coefficients(pk2[0].a2())[0]))
    send(s,str(elem_to_coefficients(pk2[0].a2())[1]))
    send(s,str(elem_to_coefficients(pk2[0].a3())[0]))
    send(s,str(elem_to_coefficients(pk2[0].a3())[1]))
    send(s,str(elem_to_coefficients(pk2[0].a4())[0]))
    send(s,str(elem_to_coefficients(pk2[0].a4())[1]))
    send(s,str(elem_to_coefficients(pk2[0].a6())[0]))
    send(s,str(elem_to_coefficients(pk2[0].a6())[1]))
    send(s,str(elem_to_coefficients(pk2[1][0])[0]))
    send(s,str(elem_to_coefficients(pk2[1][0])[1]))
    send(s,str(elem_to_coefficients(pk2[1][1])[0]))
    send(s,str(elem_to_coefficients(pk2[1][1])[1]))
    send(s,str(elem_to_coefficients(pk2[2][0])[0]))
    send(s,str(elem_to_coefficients(pk2[2][0])[1]))
    send(s,str(elem_to_coefficients(pk2[2][1])[0]))
    send(s,str(elem_to_coefficients(pk2[2][1])[1]))

def oracle(Ei, P, Q, ciphertext, s):
    pk2 = Ei,P,Q
    send_key(s,pk2)
    receive_until(s, ":")
    send(s, ciphertext.encode("hex"))
    result = receive_until(s, [".","!"])
    return "Good" in result
    

def recover_coefficients(Ea,R,S,oracle, ciphertext, s):
    x = 0
    ZE = Zmod(3^e3)
    for i in range(e3-2):
        print("Recovering 3^%d coefficient" % i)
        theta = 1/ZE(1+3^(e3-1-i))
        theta = theta.nth_root(2)
        found_coeff = 0
        for case in range(1,3):
            phiPb = (int(theta)*R-int(theta*3^(e3-i-1)*(x+case*3**i))*S)
            phiQb = int(theta*(1+3^(e3-i-1)))*S
            if oracle(Ea, phiPb, phiQb, ciphertext, s):
                found_coeff = case
                break;
        print('coefficient', found_coeff, 'for power 3^'+str(i))
        x+=found_coeff*3**i
    return x

def read_a(s):
    a = receive_until(s,"\n")
    a = re.findall("\d+",a)
    a = parse_K_elem(a[1], a[2])    
    return a

def read_point(s):
    p = receive_until(s,"\n")
    p = re.findall("\d+",p)
    p = parse_K_elem(p[0], p[1])    
    return p

def read_inputs(s):
    print("reading inputs")
    print(receive_until(s,"\n"))
    a1 = read_a(s)
    a2 = read_a(s)
    a3 = read_a(s)  
    a4 = read_a(s)
    a6 = read_a(s)
    Ei = EllipticCurve(K, [a1,a2,a3,a4,a6])
    Px = read_point(s)
    Py = read_point(s)
    P = Ei(Px, Py)
    Qx = read_point(s)
    Qy = read_point(s)
    Q = Ei(Qx, Qy)
    return (Ei, P, Q)

def PoW(s):
    data = receive_until(s, "\n")
    print(data)
    prefix = re.findall("with (.*) of length", data)[0]
    length = 18
    print(prefix)
    for perm in itertools.product(string.ascii_letters + string.digits, repeat=length - len(prefix)):
        data = prefix + "".join(perm)
        digest = hashlib.sha256(data).hexdigest()
        if digest.endswith("fffffff"):
            print("found pow!")
            send(s, data)
            break

def main():
    port = 31337
    host = "149.28.9.162"
    s = nc(host, port)
    PoW(s)
    #host = "localhost"
    #port = 12345
    #s = nc(host, port)

    sk2 = randint(1,2^e2-1)
    pk2 = isogen2(sk2)
    Ei,P,Q = pk2
    R = P
    S = Q
    pk3 = read_inputs(s)
    shared = isoex2(sk2, pk3)
    key = hashlib.sha256(elem_to_bytes(shared)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext=b"Hello world.\x00\x00\x00\x00"
    ciphertext = cipher.encrypt(plaintext)
                
    res = recover_coefficients(Ei, R, S, oracle, ciphertext, s)
    print('recovered',res)
    limit = e3
    for a in range(3):
        for b in range(3):
            secret = res+a*3**(limit-1)+b*3**(limit-2)
            super_secret_hash = hashlib.sha256(str(secret).encode('ascii')).digest()[:16]
            ciphertext = cipher.encrypt(super_secret_hash)
            send_key(s, pk2)
            send(s,ciphertext.encode("hex"))
            response = s.recv(9999)
            print(response)
    interactive(s)

if __name__ == '__main__':
    main()
