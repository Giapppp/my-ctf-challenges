from sage.all import *
from pwn import *
import ast

target = process(["python3", "unredacted_chall.py"])
n = ast.literal_eval(target.recvline().decode().strip().split("=")[1])

def get_point():
    target.recvuntil(b"Exit\n")
    target.sendlineafter(b">", b"1")
    target.recvline()
    pnt = ast.literal_eval(target.recvline().decode().strip()[10:])
    return pnt

print("Collect points...")
pnt = get_point()
print("Done")
c = ((pnt[1] - 1337)**3 - pnt[0]**2) % n
print(f"{c = }")
print(f"{n = }")

target.recvuntil(b"Exit\n")
target.sendlineafter(b">", b"2")
ss = ast.literal_eval(target.recvline().decode().strip()[len("Sums (x+y):"):])

x1, y1, x2, y2, x3, y3 = PolynomialRing(Zmod(n), 'x1, y1, x2, y2, x3, y3').gens()

I = Ideal([
    (y1 - 1337)**3 - x1**2,
    (y2 - 1337)**3 - x2**2,
    (y3 - 1337)**3 - x3**2,
    x1 + y1 - ss[0],
    x2 + y2 - ss[1],
    x3 + y3 - ss[2],
    (ss[0] - 1337) * x2 * x3 + (ss[1] - 1337) * x1 * x3 + (ss[2] - 1337) * x2 * x1 - 3 * x1 * x2 * x3
]).groebner_basis()
print("Gb done")

ans = []
for eq in I:
    ans.append(int(-list(eq)[1][0]))

target.sendlineafter(b"Your reveal: ", str(ans).encode())
target.interactive()