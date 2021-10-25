# Pinhole (crypto, 134p, 31 solved)

## Description

```
Pinholes sometimes automatically closed after a period of time to minimize the security exposure. 
What about this pinhole?
```

## Task analysis

In the task we get [encryption code](pinhole.sage) and [output](output.txt)

What we really care about is just:

```sage
def encrypt(msg, pubkey):
    X, Y = pubkey
    C = Y
    for b in msg:
        C *= X ** (int(b) + 1) * Y
    return C
```

Value of `msg` here is in binary, so inside the loop `b` is either `0` or `1`, and therefore we multiply by `X^2*Y` or by `X*Y` every time.

For example for input `0011` we get result `(X*Y)*(X*Y)*(X^2*Y)*(X^2*Y)`.
`X` and `Y` are matrices, so the multiplication order matters.

Rest of the code generates large matrices of large polynomials.

## Solution

### Observations

1. `X` and `Y` have integer coefficients and therefore results of their multiplication will also have integer coefficients.
2. If we can figure out if last multiplied matrix was `X*Y` or `X^2*Y` then we know last bit of the plaintext.

The idea is that we can multiply the `ct` by `Y^-1`, then by `X^-1` and finally if another multiplication by `X^-1` gives fraction coefficients it means we didn't have `X^2` but just `X` and therefore bit was `0`.
The other case is generally ambigious - normally it would be possible to get integer coefficients "by accident", but it seems it's not the case here.
Possibly `X` and `Y` were selected to prevent this.

### Solution overview

The idea is pretty simple:

1. Multiply `ct` by `Y^-1` and then twice by `X^-1` to get `new_ct`
2. Check if resulting matrix has fractional coefficients, in such case add bit `0` to result and set `ct = ct*Y^-1*X^-1`, otherwise add bit `1` to result and set `ct = new_ct`
3. Proceed like this until elements of matrix are not all 0

### Solver

Core of the solver is just:

```sage
def decrypt_msg(ct, X, Y, steps):
    res = []
    for i in range(steps):
        bit, ct = invert_single_bit(ct,X,Y)
        res.append(bit)
        print(bits_to_string(res[::-1]))
    return res[::-1]
    
def invert_single_bit(ct, X, Y):
    step1 = ct*Y^-1
    step2 = step1*(X^-1)
    step3 = step2*(X^-1)
    if has_integer_coeffs(step3):
        return 1, step3
    else:
        return 0, step2

def has_integer_coeffs(pol):
    for x in pol:
        for y in x:
            if y.denominator() != 1:
                return False
    return True
```

The harder part of the solver turned out to be... loading input data.
Not only output we got was a 7MB file with very long polynomials, but to make matters worse, it was just a matrix printout from sage.
For those unfamiliar with sage, when it prints the matrix it does so as:

```
[A B]
[C D]
```

Notice that there is no separator between `A` and `B` or `C` and `D`.
For numbers it would not be tragic, but consider polynomial matrix (`X` from our task):

```
[ 1235*x^2 - 4196*x + 2802185 4225*x^2 - 14356*x + 9559410]
[  -361*x^2 + 1227*x - 821422 -1235*x^2 + 4198*x - 2802211]
```

Note, each row has 2 columns! Can you spot the split point?

In the end we "fixed" this by hand, by adding `,` in the right places, so we can just import this as python code.
We got [fixed output](output.sage), then run this file through sage and renamed resulting python file from `output.sage.py` to `output.py`, so then in the code we can just do `import output`

Still, it's pretty clear author has not thought this through and didn't make a solver working with output file we got.

We can finally plug data to our solver:

```sage
def solve():
    R.<x> = ZZ[]
    X = Matrix([[1235 * x ^ 2 - 4196 * x + 2802185, 4225 * x ^ 2 - 14356 * x + 9559410], [-361 * x ^ 2 + 1227 * x - 821422, -1235 * x ^ 2 + 4198 * x - 2802211]])

    Y = Matrix([[-779 * x ^ 4 - 2829 * x ^ 3 + 205 * x ^ 2 + 252 * x + 40630633, -2665 * x ^ 4 - 9676 * x ^ 3 + 697 * x ^ 2 + 863 * x + 138967416], [228 * x ^ 4 + 828 * x ^ 3 - 60 * x ^ 2 - 73 * x - 11893098, 780 * x ^ 4 + 2832 * x ^ 3 - 204 * x ^ 2 - 250 * x - 40677503]])
    
    from output import enc
    ct = Matrix([enc[0],enc[1]])
    bits = decrypt_msg(ct,X,Y,220)
    print(bits_to_string(bits))
    
solve()
```

And we get back: `L0OpHo13S_iN_cRyp705YST3mS!`
