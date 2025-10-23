import numpy as np

p = 251
n = 8


def gen_matrix(n, p):
    while True:
        M = np.random.randint(0, p, size=(n, n))
        if np.linalg.matrix_rank(M % p) == n:
            return M % p

A = gen_matrix(n, p)
B = gen_matrix(n, p)

def str_to_blocks(s):
    data = list(s.encode())
    length = ((len(data) - 1) // n) + 1
    data += [0] * (n * length - len(data))  # padding
    blocks = np.array(data, dtype=int).reshape(length, n)
    return blocks

def encrypt_blocks(blocks):
    C = []
    for i in range(len(blocks)):
        if i == 0:
            c = (A @ blocks[i]) % p
        else:
            c = (A @ blocks[i] + B @ blocks[i-1]) % p
        C.append(c)
    return C

flag = "AIS3{Fake_FLAG}"
blocks = str_to_blocks(flag)
ciphertext = encrypt_blocks(blocks)

print("Encrypted flag:")
for c in ciphertext:
    print(c)

t = input("input: ")
blocks = str_to_blocks(t)
ciphertext = encrypt_blocks(blocks)
for c in ciphertext:
    print(c)