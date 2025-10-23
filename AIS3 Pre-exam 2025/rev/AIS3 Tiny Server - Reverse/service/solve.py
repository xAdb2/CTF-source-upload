def decrypt():
    v1 = 0
    v2 = 0x33
    v3 = 0x72
    v7 = b"rikki_l0v3"

    v8_ints = [
        0x58382033,
        0x475C2812,
        0x0F2D5229,
        0x000E0A5A,
        0x5013580F,
        0x34195A19,
        0x43333158,
        0x5A044113,
        0x2C583419,
        0x03465333,
        0x4A4A481E,
    ]

    v8_bytes = bytearray()
    for val in v8_ints:
        v8_bytes += val.to_bytes(4, byteorder='little')

    # Fill to 45 bytes if needed
    while len(v8_bytes) < 45:
        v8_bytes.append(0)

    result = ""

    while v1 < 45:
        out_byte = v2 ^ v3
        result += chr(out_byte)
        v8_bytes[v1] = out_byte
        v1 += 1
        if v1 == 45:
            break
        v2 = v8_bytes[v1]
        v3 = v7[v1 % 10]

    return result

print("[+] Correct input for sub_1E20():")
print(decrypt())
