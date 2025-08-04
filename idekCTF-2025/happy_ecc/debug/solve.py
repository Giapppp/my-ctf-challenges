from sage.all import *
from pwn import *
from tqdm import trange

io = process(["python3", "chall.py"])

def solve_PoW():
	io.recvuntil(b"b'")
	nonce = io.recvuntil(b"'")[:-1]
	io.recvuntil(b" = ")
	hsh = bytes.fromhex(io.recvline()[:-1].decode())

	for n in trange(2**28):
		if hashlib.md5(str(n).encode() + nonce).digest() == hsh:
			break

	io.sendlineafter(b"): ", str(n).encode())

solve_PoW()
p = int(io.recvline().decode().strip().split(" = ")[1])
print(f"{p = }")

Fp = GF(p)
PR, x = PolynomialRing(Fp, 'x').objgen()

def get_point():
    io.recvuntil(b"Exit\n")
    io.sendlineafter(b">", b"1")
    io.recvline()
    pu = eval(io.recvline().decode().strip().split(" = ")[1].replace("^", "**"))
    pv = eval(io.recvline().decode().strip().split(" = ")[1].replace("^", "**"))
    return pu, pv

point = [get_point() for _ in range(3)]

u = [c[0] for c in point]
v = [c[1] for c in point]

f = crt([c**2 for c in v], u)
print(f"{f = }")

C = HyperellipticCurve(f)
J = Jacobian(C)
jac = J.point_set()
c1, c2 = C.count_points(2)
N = (c2+c1**2)/2 - p
N = ZZ(N)
print(f"{N = }")
io.recvuntil(b"Exit\n")
io.sendlineafter(b">", b"2")
point = eval(io.recvline().decode().strip().split(" = ")[1].replace("^", "**"))
io.recvline()
io.sendlineafter(b">", str(N).encode())
io.interactive()
