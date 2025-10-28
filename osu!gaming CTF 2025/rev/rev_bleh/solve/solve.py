from pathlib import Path

KEY = b"PL4YING_CTFS_ISNTBETTER_THAN_OSU"

def sub_1C9(a, n):
    return (a + n) & 0xFFFFFFFF

def sub_280(a, n):
    return (a - n) & 0xFFFFFFFF

def sub_337(a1, a2, a3):
    v14 = sub_1C9(a1, 6)
    v10 = sub_1C9(a2, 128)
    v6  = sub_280(a3, 128)
    t = (v6 + (v10 ^ v14)) & 0xFFFFFFFF
    return t & 0xFF

def recover_s_from_q_bytes(q_bytes):
    target = q_bytes
    state = 0x1337
    recovered = bytearray(32)
    for i in range(32):
        desired = target[i]
        found = None
        for c in range(256):
            if sub_337(c, KEY[i], state) == desired:
                found = c
                break
        if found is None:
            return None
        recovered[i] = found
        state = desired
    return bytes(recovered)

s = b""  # <-- 用 bytes

for i in range(3842):
    input_file = "bleh" + str(i)
    path = Path(input_file)
    with path.open("rb") as f:
        f.seek(0x15BA)
        q_bytes = f.read(8)
        f.seek(0x15C4)
        q_bytes += f.read(8)
        f.seek(0x15D6)
        q_bytes += f.read(8)
        f.seek(0x15E0)
        q_bytes += f.read(8)

    print(f"[{i}] q_bytes: {q_bytes.hex()}")
    recovered = recover_s_from_q_bytes(q_bytes)
    if recovered is None:
        print(f"    [!] failed to recover s from {input_file}")
        continue

    s += recovered  # <-- bytes 相加
    print(f"    Recovered s length so far: {len(s)}")

# 最後可以寫成檔案
with open("all_recovered.bin", "wb") as f:
    f.write(s)
print(f"[+] Finished! Total bytes: {len(s)}")


