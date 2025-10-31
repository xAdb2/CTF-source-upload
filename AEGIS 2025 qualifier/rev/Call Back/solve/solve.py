# 反推並驗證 sub_7FF6171E5040 的輸入
import struct

v12 = [
    0x6E6732F63277168A,
    0x426306DC420BFEF2,
    0x5A5BFCC65C8956D8,
    0x62397CD2602358EA,
    0x42230CD8142F2AE6
]
v13 = 1847588040
# build expected 44 bytes (little-endian in-memory)
target = b"".join(struct.pack("<Q", x) for x in v12) + struct.pack("<I", v13)

C = 0x94E590
v8 = [0]*44
for j in range(0, 44, 4):
    V = (target[j] << 24) | (target[j+1] << 16) | (target[j+2] << 8) | (target[j+3])
    X = (V - 20) & 0xFFFFFFFF
    Y = X ^ C

    v2 = (Y >> 1) & 0xFFFFFFFF
    v8[j+0] = (v2 >> 24) & 0xFF
    v8[j+1] = (v2 >> 16) & 0xFF
    v8[j+2] = (v2 >> 8)  & 0xFF 
    v8[j+3] = v2 & 0xFF

# a1 is v8 with pairwise swap inverted: a1[n] = v8[n ^ 1]
a1 = bytes(v8[n ^ 1] for n in range(44))
print("recovered:", a1)
print("as ascii:", a1.decode())
