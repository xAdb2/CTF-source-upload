# decrypt_flag.py
import base64

def decrypt_flag(b64_string: str) -> bytes:
    data = base64.b64decode(b64_string)
    key = bytes([0x1A, 0x2B, 0x3C])
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

if __name__ == "__main__":
    b64 = "W257U3hHXURjfERORUlOdUBZRUJSRV9Uc1hjfUpRfwpB"
    decoded = decrypt_flag(b64)
    try:
        print(decoded.decode('utf-8'))
    except UnicodeDecodeError:
        print("Decoded bytes (hex):", decoded.hex())
