# 最後的 flag（XOR 後的結果）
final_flag = [
    0x5a, 0x60, 0x61, 0x0f, 0x08, 0x29, 0x42, 0x32, 0x25, 0x23, 0x42, 0x68, 0x4b, 0x41, 0x63, 0x55,
    0x37, 0x43, 0x6a, 0x50, 0x40, 0x6f, 0x2e, 0x66, 0x49, 0x7f, 0x09, 0x66, 0x79, 0x7c, 0x37, 0x18,
    0x5d, 0x35, 0x46, 0x41, 0x37, 0x0f, 0x19, 0x1c, 0x30, 0x79, 0x29, 0x69, 0x0a, 0x46, 0x3b
]

# 讀取 XOR 操作 log 檔
with open("flag_xor_log.txt", "r") as f:
    lines = [line.strip() for line in f if line.strip()]

# 擷取每組 XOR 操作
ops = []
for i in range(0, len(lines), 2):
    top = int(lines[i][5:-1])  # e.g. "flag[40]"
    dest = int(lines[i + 1].split(']')[0].split('[')[1])  # e.g. "flag[0] = ..."
    ops.append((dest, top))

# 反向操作 XOR（因為 XOR 可逆）
ops.reverse()
flag = final_flag.copy()
for dest, top in ops:
    flag[dest] ^= flag[top]

# 輸出 ASCII
print("Recovered flag (ascii):", ''.join(chr(b) if 32 <= b < 127 else '.' for b in flag))
print("Recovered flag (hex):", flag)
re = ""

for i in flag:
    re += chr(i)

print(re)