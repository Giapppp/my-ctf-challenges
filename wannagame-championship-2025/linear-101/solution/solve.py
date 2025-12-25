from pwn import *
import random

# target = process(["python3", "chall.py"]) 
# target = remote("localhost", "1339")
target = remote("challenge.cnsc.com.vn", "30463")
context.log_level = 'info'

n = 128
random.seed("Wanna Win?")

def solve_round(round_num):
    A = [random.randbytes(n) for _ in range(n)]

    target.recvuntil(b"b = ")
    b_str = target.recvline().strip().decode()
    b = eval(b_str)

    x_sol = []
    
    for j in range(n):
        upper_bound = float('inf')
        
        for i in range(n):
            diff = b[i] - A[i][j]
            if diff < upper_bound:
                upper_bound = diff

        if upper_bound > 255:
            upper_bound = 255

        if upper_bound < 0:
            upper_bound = 0
            
        x_sol.append(int(upper_bound))

    sol_bytes = bytes(x_sol)
    target.sendlineafter(b"x = ", sol_bytes.hex().encode())
    log.info(f"Round {round_num + 1}/64 solved")

try:
    for i in range(64):
        solve_round(i)

    target.interactive()
except Exception as e:
    log.error(f"Exploit failed: {e}")