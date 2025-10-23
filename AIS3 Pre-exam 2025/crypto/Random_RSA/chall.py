# chall.py
from Crypto.Util.number import getPrime, bytes_to_long
from sympy import nextprime
from gmpy2 import is_prime

FLAG = b"AIS3{Fake_FLAG}"

a = getPrime(512)
b = getPrime(512)
m = getPrime(512)
a %= m
b %= m
seed = getPrime(300)

rng = lambda x: (a*x + b) % m


def genPrime(x):
    x = rng(x)
    k=0
    while not(is_prime(x)):
        x = rng(x)
    return x

p = genPrime(seed)
q = genPrime(p)

n = p * q
e = 65537
m_int = bytes_to_long(FLAG)
c = pow(m_int, e, n)

# hint
seed = getPrime(300)
h0 = rng(seed)
h1 = rng(h0)
h2 = rng(h1)

with open("output.txt", "w") as f:
    f.write(f"h0 = {h0}\n")
    f.write(f"h1 = {h1}\n")
    f.write(f"h2 = {h2}\n")
    f.write(f"M = {m}\n")
    f.write(f"n = {n}\n")
    f.write(f"e = {e}\n")
    f.write(f"c = {c}\n")