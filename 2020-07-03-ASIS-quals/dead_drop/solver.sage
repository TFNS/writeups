
def bytes_to_long(data):
    return int(data.encode('hex'), 16)


def long_to_bytes(data):
    data = int(data)
    data = hex(data).rstrip('L').lstrip('0x')
    if len(data) % 2 == 1:
        data = '0' + data
    return data.decode("hex")

def legendre_GF2(x, mod):
    assert kronecker(x, mod) != 0
    return (kronecker(x, mod) + 2) % 3

def solve(mod, enc, flag):
    matrix_eq  = []
    vector_res = []

    for a, a_s in enc:
        a_s = legendre_GF2(a_s % mod, mod)
        a   = [legendre_GF2(x % mod, mod) for x in a]
        
        vector_res.append(a_s)
        matrix_eq.append(a)

    for i in range(len(flag)):
        if flag[i] == None:
            continue
        new_eq    = [0] * len(flag)
        new_eq[i] = 1

        matrix_eq.append(new_eq)
        vector_res.append(flag[i])

    A = Matrix(GF(2), matrix_eq)
    B = vector(GF(2), vector_res)

    res = A.solve_right(B)

    res_string = ''
    for c in res:
        res_string += str(c)

    return long_to_bytes(int(res_string, 2))


def main1():
    with open('flag1.enc', 'rb') as f:
        p = int(f.readline().strip())
        enc = eval(f.readline())
        # Factorisation of p is 19 * 113 * 2657 * 6823 * 587934254364063975369377416367
        mod = 587934254364063975369377416367
        flag = [None] * len(enc)
        start = bin(bytes_to_long(b'ASIS{'))[2:]
        end   = bin(bytes_to_long(b'}'))[2:].zfill(8)
        # We know the end of the flag
        for i in range(len(start)):
            flag[i] = int(start[i])
        # We know the start of the flag
        for i in range(-1, -len(end) - 1, -1):
            flag[i] = int(end[i])
        result = solve(mod, enc, flag)
        print(result)

def main2():
    with open('flag2.enc', 'rb') as f:
        p = mod = int(f.readline().strip())
        enc = eval(f.readline())
        flag = [None] * len(enc)
        result = solve(mod, enc, flag)
        print('ASIS{'+result+'}')

main1()
main2()

