from sage.all import *
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from base64 import b85encode
from hashlib import sha256

def b85_decode(inp):
    return subprocess.check_output(["./b85tohex", inp]).decode().strip()

def b85_encode(inp):
    return subprocess.check_output(["./hextob85", inp])

def get_sig(msg: bytes):
    io.sendlineafter(b"Verify(1):", b"0")
    io.recvline()
    io.sendline(msg)
    sig1 = int(b85_decode(io.recvline()[len("sig = "):-1].decode().strip()), 16)
    return sig1

io = process(["./chall"])
# io = remote("localhost", "1337")
# io = remote("challenge.cnsc.com.vn","32707")
Nb = bytes.fromhex(b85_decode(io.recvline()[4:-1].decode().strip()))
N = bytes_to_long(Nb)

sample = 10
hints = []

for _ in range(sample):
    msg = b85encode(os.urandom(64))[:-1]
    b1 = b"A"
    b2 = bytes([Nb[0]])

    msg1 = msg + b1
    msg2 = msg + b2
    sig1 = get_sig(msg1)
    sig2 = get_sig(msg2)

    N1 = bytes_to_long(b1 + Nb[1:])
    N2 = bytes_to_long(b2 + Nb[1:])

    l = crt([sig1, sig2], [N1, N2])
    assert l.bit_length() < 4097
    hints.append(l)

l = len(hints)
B = matrix(ZZ, hints).right_kernel_matrix(algorithm="pari")[:-2]

Br, Bc = B.dimensions()
L = block_matrix(ZZ, [[B.T, identity_matrix(Bc)]])
L[:, :Br] *= 2**3000
Lrd = L.LLL()

v = []
for i in range(Lrd.nrows()):
    if all([c == 0 for c in Lrd[i][:Br]]):
        v.append(Lrd[i][Br:])

h = vector(ZZ, hints)
prime = set()

for aa in range(-10, 10):
    for bb in range(-10, 10):
        for cc in range(-10, 10):
            z = aa * v[0] + bb * v[1] + cc * v[2]
            x = h - z
            for c in x:
                pi = gcd(c, N)
                if pi != 1 and pi < N:
                    prime.add(pi)

msg = b"1_d4r3_y0u_70_519n_7h15_3x4c7_51x7y_f0ur_by73_57r1n9_w17h_my_k3y"
h = bytes_to_long(sha256(msg).digest())
d = pow(0x10001, -1, prod([pi - 1 for pi in prime]))
s = long_to_bytes(pow(h, d, N))

io.sendlineafter(b"Verify(1):", b"1")
io.recvline()
io.sendline(b85_encode(s.hex()))
io.interactive()