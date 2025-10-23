# 檔案名稱
input_file = "encrypted_image_notchange.png"
output_file = "decrypted_image.png"

def decode_byte(b):
    return ((b - 4) & 0xFF) ^ 0x72

with open(input_file, "rb") as f_in:
    encrypted_data = f_in.read()

# 對每個 byte 做處理
decrypted_data = bytes(decode_byte(b) for b in encrypted_data)

# 寫入解密後的檔案
with open(output_file, "wb") as f_out:
    f_out.write(decrypted_data)

print(f"[+] 解密完成，輸出檔案：{output_file}")
