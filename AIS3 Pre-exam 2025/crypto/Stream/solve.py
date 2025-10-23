#!/usr/bin/env python3
from math import isqrt
from Crypto.Util.number import long_to_bytes

# 1. 讀取 output.txt，取最後一行 hex（前 80 行全是干擾）
with open('output.txt', 'r') as f:
    lines = [l.strip() for l in f if l.strip()]
cipher_hex = lines[-1]                  # 形如 "0xabcdef..."
C = int(cipher_hex, 16)

known_prefix = b"AIS3{"                # 已知開頭
recovered_flag = None

# 2. 嘗試不同的 flag 長度 N（bytes），一般不會超過 100 bytes
for N in range(len(known_prefix), 100):
    # 把 C 右移 8*N 位，理論上等於 r^2 >> (8*N)
    A = C >> (8 * N)
    if A == 0:
        # 如果 A == 0，代表 N 可能太大（整個 r^2 都被右移掉了），可以跳過
        continue

    # 如果 A 正好是某個整數的平方，才可能對應到某個 r_high
    r_high = isqrt(A)
    if r_high * r_high != A:
        # 不是完全平方 → 這個 N 一定不對
        continue

    # 到這裡表示找到「高位平方吻合」：A == r_high^2
    # 把 r_high^2 << (8*N) 當作 r^2 的高位部分
    high_part = (r_high * r_high) << (8 * N)

    # 由於 C = flag_int ⊕ r^2，則 flag_int = C ⊕ r^2
    # 這裡以 high_part 代表 r^2 的高位，temp 就能拿到 r^2 的低 8N 位 XOR flag_int
    temp = C ^ high_part

    # 只要低 8N 位是 flag_int，就把它截取下來
    # temp 可能會比 2^(8N) 小，也可能大；但 to_bytes 需要確切知道 N bytes
    try:
        flag_candidate = (temp & ((1 << (8 * N)) - 1)).to_bytes(N, 'big')
    except OverflowError:
        continue

    # 檢查「已知前綴」＋末尾 '}'，簡單驗證一下
    if flag_candidate.startswith(known_prefix) and flag_candidate.endswith(b'}'):
        recovered_flag = flag_candidate
        print(f"[+] 找到可能的 flag 長度 N = {N}")
        print("[+] 還原出的 flag:", flag_candidate.decode())
        break

if recovered_flag is None:
    print("[-] 無法從 output.txt 還原 flag，請檢查檔案或修改 N 的搜尋範圍。")
