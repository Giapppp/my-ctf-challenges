# The PoW is extracted from https://github.com/soon-haari/my-ctf-challenges/blob/main/2024-codegate/%5BCrypto%5D-%5BGreatest-Common-Multiple%5D/prob/for_organizer/src/secret.py
import hashlib
import random
import string

def PoW(bits):
	n = random.randrange(0, 2**bits)
	a = "".join(random.choices(string.ascii_letters, k=20)).encode()
	hsh = hashlib.md5(str(n).encode() + a).digest()

	print(f"md5(str(n).encode() + {a}).hexdigest() = {bytes.hex(hsh)}")
	if int(input(f"Input the decimal result of n within range(2**{bits}): ")) != n:
		exit()