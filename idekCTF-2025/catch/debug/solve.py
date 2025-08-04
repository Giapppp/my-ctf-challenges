from sage.all import *
from Crypto.Util.number import *
from pwn import *
import ast
from tqdm import trange

limit = 0xe5db6a6d765b1ba6e727aa7a87a792c49bb9ddeb2bad999f5ea04f047255d5a72e193a7d58aa8ef619b0262de6d25651085842fd9c385fa4f1032c305f44b8a4f92b16c8115d0595cebfccc1c655ca20db597ff1f01e0db70b9073fbaa1ae5e489484c7a45c215ea02db3c77f1865e1e8597cb0b0af3241cd8214bd5b5c1491f
Fp = GF(limit)

io = process(["python3", "chall.py"])

def solve():
    io.recvline()
    start = ast.literal_eval(io.recvline().decode().strip().split(": ")[1])
    mind = bytes.fromhex(io.recvline().decode().strip().split(": ")[1])
    io.recvline()
    end = ast.literal_eval(io.recvline().decode().strip().split(": ")[1])

    start = vector(Fp, start)
    end = vector(Fp, end)
    mat = [[int.from_bytes(mind[i:i+8][j:j+2], "big") for j in range(0, 8, 2)] for i in range(0, len(mind), 8)]
    fpmat = [Matrix(Fp, [[c[0], c[1]], [c[2], c[3]]]) for c in mat]
    fpmat_ = [fmat.inverse() for fmat in fpmat]

    tbl = [(end, []) for _ in range(len(fpmat_))]

    while True:
        new_tbl = []
        for ele in tbl:
            end, step = ele
            for idx in range(len(fpmat_)):
                check = fpmat_[idx] * end
                if int(check[0]).bit_length() < limit.bit_length() - 40:
                    step = fpmat[idx].change_ring(ZZ).list() + step
                    new_tbl.append((check, step))
                if check == start:
                    return step
        tbl = new_tbl

for _ in trange(20):
    anslist = solve()
    ans = b"".join([int(c).to_bytes(2, "big") for c in anslist])
    io.sendlineafter(b"recall (hex): ", ans.hex().encode())
    io.recvline()

io.interactive()
