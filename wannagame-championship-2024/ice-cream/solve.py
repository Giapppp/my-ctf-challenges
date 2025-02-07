from sage.all import *
from pwn import *
from lll_cvp import * # https://github.com/maple3142/lll_cvp/blob/master/lll_cvp.py
from Crypto.Util.number import *
from tqdm import trange
from hashlib import sha256

#https://github.com/rkm0959/Implementations/tree/main/Half_GCD
def HGCD(a, b):
    if 2 * b.degree() <= a.degree() or a.degree() == 1:
        return 1, 0, 0, 1
    m = a.degree() // 2
    a_top, a_bot = a.quo_rem(x**m)
    b_top, b_bot = b.quo_rem(x**m)
    R00, R01, R10, R11 = HGCD(a_top, b_top)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    q, e = c.quo_rem(d)
    d_top, d_bot = d.quo_rem(x**(m // 2))
    e_top, e_bot = e.quo_rem(x**(m // 2))
    S00, S01, S10, S11 = HGCD(d_top, e_top)
    RET00 = S01 * R00 + (S00 - q * S01) * R10
    RET01 = S01 * R01 + (S00 - q * S01) * R11
    RET10 = S11 * R00 + (S10 - q * S11) * R10
    RET11 = S11 * R01 + (S10 - q * S11) * R11
    return RET00, RET01, RET10, RET11
    
def GCD(a, b):
    print(a.degree(), b.degree())
    q, r = a.quo_rem(b)
    if r == 0:
        return b
    R00, R01, R10, R11 = HGCD(a, b)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    if d == 0:
        return c.monic()
    q, r = c.quo_rem(d)
    if r == 0:
        return d
    return GCD(d, r)

e = 33751

# target = process(["python3", "chall.py"])
target = remote("154.26.136.227", 59164)
target.sendlineafter(b" > ", f"{2**16}".encode())
target.recvline()
value = []
for _ in trange(2**16):
    recv = int(target.recvline().decode().strip(), 16)
    value.append(recv)

def coeffs(n):
    C = 1
    ans = []
    for j in range(1, n+1):
        ans.append(C)
        C = - C * (n - j) // j
    return ans

kN = sum(x * y for x, y in zip(coeffs(33757), value))
tN = sum(x * y for x, y in zip(coeffs(33767), value))
N = int(gcd(kN, tN))
if 2046 < N.bit_length() < 2049:
    while N % 2 == 0:
        N //= 2

print(N)

K = Zmod(N)
x = PolynomialRing(K, 'x').gen()
#(x + ky)^e => (ky/x + 1)**e
f1 = (x + 1)**e - (K(value[1])/K(value[0]))
f2 = (2 * x + 1)**e - (K(value[2])/K(value[0]))
f = GCD(f1, f2)
z = int(-f[0]/f[1])
#y/x = z (mod N) => y - zx + kN = 0
M = Matrix([[1, 1, 0],
            [-z, 0, 1],
            [N, 0, 0]])

lb = [0, 2**383, 2**383]
ub = [0, 2**384, 2**384]

ans = solve_inequality(M, lb, ub)
print(ans)
secret2, secret1 = [int(c) for c in ans[1:]]
assert isPrime(secret1)
assert isPrime(secret2)
print(secret1, secret2)

icecream = pow(secret1 + (2**16) * secret2, e, N)
target.recvline()
target.sendline(f"{icecream}".encode())

target.interactive()