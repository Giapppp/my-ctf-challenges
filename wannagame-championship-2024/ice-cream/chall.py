from Crypto.Util.number import *
from hashlib import sha256
import signal

def timeout_handler(sig, frame):
    print('Time is out...')
    exit(0)

class IceCream:
    def __init__(self, nbit: int):
        self.p = getPrime(nbit//2)
        self.q = getPrime(nbit//2)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
#        self.e = getPrime(16) # a harder version
        self.e = 33751
        self.secret1 = getPrime(384)
        self.secret2 = getPrime(384)
        self.d = inverse(self.e, self.phi)

    def wrap(self):
        c = pow(self.secret1, self.e, self.n)
        self.secret1 += self.secret2
        return c

def main():
    signal.alarm(500)
    cart = IceCream(2048)
    cnt = int(input("I can give you some icecreams to try, so how many do you want ? > "))
    if cnt > 2**16:
        print("Too much...")
        exit(0)

    print("Here you are: ")
    for _ in range(cnt):
        icecream = cart.wrap()
        print(f"{hex(icecream)}")
    challenge_icecream = cart.wrap()

    print("Can you make an icecream with the same flavor as mine ?")
    your_icecream = int(input())
    if your_icecream == challenge_icecream:
        print("Woah! You deserve for the gift!")
        print(open("flag.txt", "r").read())
    else:
        print("You eat too much and do nothing...")
        print(challenge_icecream)
        exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGALRM, timeout_handler)
    main()
