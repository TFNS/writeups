from Crypto.Util.number import inverse, getPrime, isPrime
from Crypto.Random.random import randrange

class FiniteGeneralLinearGroup(object):
    """FiniteGeneralLinearGroup
    Calculates over GL_n(F_p)
    """
    def __init__(self, n, p=None, bits=512):
        """ Initialize and reset this instance """
        if p:
            self.p = p
        else:
            self.p = getPrime(bits)
        
        self.n = n
        self.A = [
            [0 for j in range(self.n)]
            for i in range(self.n)
        ]
        return
    
    def set_random(self):
        """ Set each elements to random numbers """
        for i in range(self.n):
            for j in range(self.n):
                self.set_at((j, i), randrange(self.p))
        return

    def set_at(self, pos, a):
        """ Set an element """
        assert len(pos) == 2
        assert 0 <= pos[0] < self.n and 0 <= pos[1] < self.n
        
        self.A[pos[1]][pos[0]] = a % self.p
        return

    def get_at(self, pos):
        """ Get an element """
        assert len(pos) == 2
        assert 0 <= pos[0] < self.n and 0 <= pos[1] < self.n
        
        return self.A[pos[1]][pos[0]]

    def determinant(self):
        """ Calculate determinant """
        if self.n == 1: return self.get_at((0, 0))
        det = 0
        for k in range(self.n):
            X = FiniteGeneralLinearGroup(self.n - 1, p = self.p)
            for i in range(self.n):
                if i == k: continue
                for j in range(1, self.n):
                    ii = i if i <= k else i - 1
                    X.set_at((j - 1, ii), self.get_at((j, i)))
            sgn = 1 if k % 2 == 0 else -1
            det += sgn * self.get_at((0, k)) * X.determinant()
        return det

    def transpose(self):
        """ Transpose me """
        X = FiniteGeneralLinearGroup(self.n, p = self.p)
        for i in range(self.n):
            for j in range(self.n):
                X.set_at((j, i), self.get_at((i, j)))
        return X
    
    def __add__(self, B):
        """ Define addition """
        assert B.n == self.n
        X = FiniteGeneralLinearGroup(self.n, p = self.p)
        for i in range(self.n):
            for j in range(self.n):
                X.set_at((j, i), (self.get_at((j, i)) + B.get_at((j, i))) % self.p)
        return X

    def __sub__(self, B):
        """ Define subtraction """
        assert B.n == self.n
        X = FiniteGeneralLinearGroup(self.n, p = self.p)
        for i in range(self.n):
            for j in range(self.n):
                X.set_at((j, i), (self.get_at((j, i)) - B.get_at((j, i))) % self.p)
        return X
    
    def __mul__(self, B):
        """ Define multiplication """
        X = FiniteGeneralLinearGroup(self.n, p = self.p)
        if isinstance(B, FiniteGeneralLinearGroup):
            # Multiplied by FGLG
            assert B.n == self.n
            for i in range(self.n):
                for j in range(self.n):
                    x = 0
                    for k in range(self.n):
                        x += self.get_at((k, i)) * B.get_at((j, k))
                    X.set_at((j, i), x % self.p)
        elif isinstance(B, int) or isinstance(B, float):
            # Multiplied by integer
            for i in range(self.n):
                for j in range(self.n):
                    X.set_at((j, i), self.get_at((j, i)) * B % self.p)
        else:
            raise ValueError()
        return X
    
    def __pow__(self, e):
        """ Define power """
        if not isinstance(e, int):
            raise ValueError()
        
        X = FiniteGeneralLinearGroup(self.n, p = self.p)
        if e < 0:
            # Inverse power
            if self.determinant() == 0:
                raise ValueError()
            Y = FiniteGeneralLinearGroup(self.n, p = self.p)
            for i in range(self.n):
                for j in range(self.n):
                    Z = FiniteGeneralLinearGroup(self.n - 1, p = self.p)
                    for k in range(self.n):
                        if k == i: continue
                        for l in range(self.n):
                            if l == j: continue
                            ii = k if k <= i else k - 1
                            jj = l if l <= j else l - 1
                            Z.set_at((jj, ii), self.get_at((l, k)))
                    sgn = 1 if (i + j) % 2 == 0 else -1
                    Y.set_at((j, i), sgn * Z.determinant() % self.p)
            Y = Y.transpose()
            for i in range(self.n):
                for j in range(self.n):
                    X.set_at((j, i), 1 if i == j else 0)
            for i in range(-e):
                X *= Y
            X *= inverse(self.determinant(), self.p)
        elif e == 0:
            # Identity
            for i in range(self.n):
                for j in range(self.n):
                    X.set_at((j, i), 1 if i == j else 0)
        elif e > 0:
            # Normal power
            for i in range(self.n):
                for j in range(self.n):
                    X.set_at((j, i), 1 if i == j else 0)
            for i in range(e):
                X *= self
        else:
            raise ValueError()
        return X

    def __eq__(self, B):
        if B.n != self.n: return False
        for i in range(self.n):
            for j in range(self.n):
                if B.get_at((j, i)) != self.get_at((j, i)): return False
        return True

    def __str__(self):
        output = '['
        for i in range(self.n):
            if i != 0: output += ' '
            output += '['
            for j in range(self.n):
                output += '{}, '.format(self.get_at((j, i)))
            output = output[:-2] + ']\n'
        return output.rstrip() + ']'
