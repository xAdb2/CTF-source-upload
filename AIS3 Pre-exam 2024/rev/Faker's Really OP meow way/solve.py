op_key = ["\x7F", "\xF7", "\x8C", "\x2B", "\xB4", "\xFD", "\x54", "\xBD", "\x80", "\x49", "\x0A", "\x4A", "\x75", "\xF4", "\xD2", "\x2D", "\xB1", "\x72", "\xC3", "\x4F", "\xBE", "\x63", "\x24", "\xE7", "\x01", "\x97", "\xFD", "\x01", "\x4F", "\x06", "\xB0", "\x4B", "\xC3", "\x86", "\x68", "\xB1"]
cmp = ["\xC0", "\x52", "\xDF", "\x5E", "\xC7", "\x8F", "\x87", "\xB9", "\xB3", "\xBB", "\x2B", "\x7B", "\xE3", "\x42", "\x8D", "\x9F", "\x7F", "\x02", "\x22", "\xE2", "\x8B", "\xC2", "\x3F", "\xD7", "\x31", "\xD5", "\xA2", "\x73", "\xE2", "\x30", "\x18", "\xEC", "\xFC", "\xC5", "\xD7", "\xCC"]
result = ""

for i in range(len(op_key)):
    br = i % 3
    if br == 0:
        if ord(cmp[i]) - ord(op_key[i]) < 0:
            result += chr(ord('\xFF') - ord(op_key[i]) + ord(cmp[i]) + 1)
        else:
            result += chr(ord(cmp[i]) - ord(op_key[i]))

    elif br == 1:
        if ord(cmp[i]) + ord(op_key[i]) > 126:
            result += chr(ord(cmp[i]) - 256 + ord(op_key[i]))
        else:
            result += chr(ord(cmp[i]) + ord(op_key[i]))
    else:
        result += chr(ord(cmp[i]) ^ ord(op_key[i]))

print(result)