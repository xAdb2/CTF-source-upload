#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# pwntools 腳本：自動化 Recover A、B 並解密 Flag Ciphertext
#
# 使用方式：
#   1. 安裝 pwntools： pip install pwntools
#   2. 修改下方的 HOST、PORT 為實際遠端服務地址與埠號
#   3. 執行： python3 solve.py
#
from pwn import *
import sys

# ----------------------------
# 設定遠端服務
# ----------------------------
HOST = "chals1.ais3.org"   # ← 改成真實主機
PORT = 18000                    # ← 改成真實埠號

# 模數和區塊大小
p = 251
n = 8

# ----------------------------
# 工具函式：將 "[ a b c ... ]" 這種一行文字解析成 list[int]
# ----------------------------
def parse_vec(line):
    """
    line 範例: "[  34  200   13  ...   45   67  128 ]"
    回傳: [34, 200, 13, ..., 45, 67, 128]
    """
    line = line.strip()
    if not (line.startswith("[") and line.endswith("]")):
        return None
    nums = line[1:-1].strip().split()
    return [int(x) for x in nums]

# ----------------------------
# 工具函式：讀取遠端回傳直到看到 "input:"，並收集中間所有 "[ ... ]" 行
# ----------------------------
def recv_blocks_until_prompt(r):
    """
    讀取多行，直到碰到 "input:" 為止。
    這些行中所有以 '[' 開頭並以 ']' 結尾的，每行都 parse 成 8 維向量。
    回傳值: list_of_vectors (每個元素都是 list[int]，長度 = 8)
    """
    blocks = []
    while True:
        line = r.recvline(timeout=5)
        if not line:
            log.failure("伺服器連線中斷或沒有回應")
            sys.exit(1)
        line = line.decode('utf-8', errors='ignore').strip()
        if line == "input:":
            # 收到 prompt，停止讀取
            break
        vec = parse_vec(line)
        if vec is not None:
            blocks.append(vec)
    return blocks

# ----------------------------
# 依照 raw_bytes 查詢 oracle，回傳該次查詢得到的所有 ciphertext blocks
# ----------------------------
def query_oracle(r, raw_bytes):
    """
    r: 已建立的 remote 連線
    raw_bytes: bytes，要送給伺服器當明文查詢
    回傳: list_of_vectors (每個都是長度 8 的 int list)
    """
    # pwntools send 時，若要傳送 raw bytes，應使用 send() 而非 sendline()
    r.send(raw_bytes + b"\n")
    return recv_blocks_until_prompt(r)

# ----------------------------
# 求模 p 下的一個數的逆元 (p 為質數)
# ----------------------------
def modinv(a, p):
    return pow(a, p - 2, p)

# ----------------------------
# 求 8×8 矩陣 X 在 mod p 下的逆矩陣 (純 Python Gauss-Jordan)
# X: list of lists, 大小 = 8×8, 元素是 0..p-1
# 回傳: invX, 同樣是 8×8 的 list of lists
# ----------------------------
def invert_matrix_mod(X, p):
    n = len(X)
    # 複製 X 並增加單位矩陣，構造增廣矩陣
    aug = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(X)]
    # Gauss-Jordan 消去
    for i in range(n):
        # 找 pivot (aug[i][i] != 0)，若此位置為 0，找下面一行做交換
        if aug[i][i] == 0:
            for k in range(i+1, n):
                if aug[k][i] != 0:
                    aug[i], aug[k] = aug[k], aug[i]
                    break
        if aug[i][i] == 0:
            log.failure(f"第 {i} 列 pivot 為 0，無法求逆")
            sys.exit(1)
        inv_pivot = modinv(aug[i][i], p)
        # 將 pivot 這行乘上 inv_pivot，使得該位置變成 1
        for col in range(2*n):
            aug[i][col] = (aug[i][col] * inv_pivot) % p
        # 消去其他列的第 i 欄
        for r_ in range(n):
            if r_ != i and aug[r_][i] != 0:
                factor = aug[r_][i]
                for col in range(2*n):
                    aug[r_][col] = (aug[r_][col] - factor * aug[i][col]) % p
    # 讀取右半邊就是逆矩陣
    invX = [row[n:] for row in aug]
    return invX

# ----------------------------
# 主程序
# ----------------------------
def main():
    # 1. 用 pwntools 連線到遠端加密 oracle
    r = remote(HOST, PORT)

    # 2. 讀取初始的 Flag Ciphertext block，直到看到 prompt "input:"
    flag_ct = recv_blocks_until_prompt(r)
    log.success(f"收到 Flag Ciphertext，共 {len(flag_ct)} 個 blocks")

    # 3. Recover A：做 8 次查詢
    A_cols = []
    for j in range(n):
        # 構造 e_j: 8 bytes, 第 j 個 byte = 1，其餘 = 0
        ej = bytes([1 if i == j else 0 for i in range(n)])
        # 送出，拿回 ciphertext block
        ct_blocks = query_oracle(r, ej)
        # 只送一 block → 回傳只會有 1 個向量
        if len(ct_blocks) < 1:
            log.failure("Recover A 時，未收到任何 ciphertext")
            sys.exit(1)
        A_cols.append(ct_blocks[0])
    # 把 A_cols (8 個 8 維向量) 水平拼成 8×8
    A = [[A_cols[j][i] % p for j in range(n)] for i in range(n)]
    log.success("成功 Recover A:")
    for row in A:
        log.info("    " + " ".join(f"{x:3d}" for x in row))

    # 4. Recover B：再做 8 次查詢 (兩塊明文：e_j, 0)
    B_cols = []
    for j in range(n):
        # 第一塊 = e_j (8 bytes)，再加一個 0x00 做第二塊開頭
        ej_plus_zero = bytes([1 if i == j else 0 for i in range(n)]) + b"\x00"
        ct_blocks = query_oracle(r, ej_plus_zero)
        # 送兩塊 → 回傳至少 2 個向量
        if len(ct_blocks) < 2:
            log.failure("Recover B 時，回傳的 ciphertext 長度不足 2")
            sys.exit(1)
        # 第二行 (index=1) 就是 B @ e_j
        B_cols.append(ct_blocks[1])
    # 拼出 B 矩陣
    B = [[B_cols[j][i] % p for j in range(n)] for i in range(n)]
    log.success("成功 Recover B:")
    for row in B:
        log.info("    " + " ".join(f"{x:3d}" for x in row))

    # 5. 求 A 的逆矩陣 (mod 251)
    Ainv = invert_matrix_mod(A, p)
    log.success("A^{-1} (mod 251) 計算完畢:")
    for row in Ainv:
        log.info("    " + " ".join(f"{x:3d}" for x in row))

    # 6. 用 Ainv, B 解密剛剛讀到的 flag_ct
    #    m_0 = Ainv * c_0
    #    m_i = Ainv * (c_i - B * m_{i-1})
    recovered_blocks = []
    for i, c_vec in enumerate(flag_ct):
        if i == 0:
            # matrix-vector multiply Ainv @ c_vec (mod p)
            m0 = [sum(Ainv[row][k] * c_vec[k] for k in range(n)) % p for row in range(n)]
            recovered_blocks.append(m0)
        else:
            # 計算 t = c_i - B * m_{i-1}
            prev = recovered_blocks[i-1]
            Bm = [sum(B[row][k] * prev[k] for k in range(n)) % p for row in range(n)]
            t = [(c_vec[k] - Bm[k]) % p for k in range(n)]
            mi = [sum(Ainv[row][k] * t[k] for k in range(n)) % p for row in range(n)]
            recovered_blocks.append(mi)

    # 7. 把所有 recovered_blocks 拼成 bytes，並去掉尾端 padding (0x00)
    all_bytes = b''.join(bytes([x]) for block in recovered_blocks for x in block)
    plaintext = all_bytes.rstrip(b'\x00')
    log.success("解密後的 Flag Bytes (去除 padding):")
    log.info(plaintext)
    try:
        flag = plaintext.decode('ascii')
    except:
        flag = plaintext.decode(errors='ignore')
    log.success(f"最終還原出 Flag: {flag}")

    # 結束連線
    r.close()

if __name__ == "__main__":
    main()
