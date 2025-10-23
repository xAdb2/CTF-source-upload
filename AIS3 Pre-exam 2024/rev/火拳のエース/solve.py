compare_key0 = "DHLIYJEG"
compare_key1 = "MZRERYND"
compare_key2 = "RUYODBAH"
compare_key3 = "BKEMPBRE"

buffer0 = [0] * 8
buffer1 = [0] * 8
buffer2 = [0] * 8
buffer3 = [0] * 8

def inverse_complex_function(key, a2):
    #v5 = (17 * a2 + a1 - 65) % 26 
    v5 = ord(key) - 65
    v4 = a2 % 3 + 3
    v2 = a2 % 3
    if a2 % 3 == 2:
        #v5 = (v5 - v4 + 26) % 26
        count = 0
        while True:
            origin_v5 = get_origin(v5, count) + v4 - 26
            a1 = check_a1(origin_v5, a2)
            if a1 == -1:
                count += 1
            else:
                return a1

    elif v2 <= 2:
        if v2:
            if v2 == 1:
                #v5 = (2 * v4 + v5) % 26
                count = 0
                while True:
                    origin_v5 = get_origin(v5, count) - (2 * v4)
                    a1 = check_a1(origin_v5, a2)
                    if(a1 == -1):
                        count += 1
                    else:
                        return a1
        else:
            #v5 = (v4 * v5 + 7) % 26
            count = 0
            while True:
                origin_v5 = (get_origin(v5, count) - 7) / v4
                if int(origin_v5) * 10 == origin_v5 * 10:
                    origin_v5 = int(origin_v5)
                    a1 = check_a1(origin_v5, a2)
                    if(a1 == -1):
                        count += 1
                    else:
                        return a1
                else:
                    count += 1

def get_origin(remainder, count):
    return 26 * count + remainder

def check_a1(origin_v5, a2):
    count = 0
    while True:
        a1 = get_origin(origin_v5, count) + 65 - (17 * a2)
        if a1 > 64 and a1 <= 90:
            return a1
        elif a1 > 90:
            return -1
        else:
            count += 1

for i in range(8):
    buffer0[i] = inverse_complex_function(compare_key0[i], i)
    buffer1[i] = inverse_complex_function(compare_key1[i], i + 32)
    buffer2[i] = inverse_complex_function(compare_key2[i], i + 64)
    buffer3[i] = inverse_complex_function(compare_key3[i], i + 96)

xor0 = ["\x0E", "\x0D", "\x7D", "\x06", "\x0F", "\x17", "\x76", "\x04"]
xor1 = ["\x6D", "\x00", "\x1B", "\x7C", "\x6C", "\x13", "\x62", "\x11"]
xor2 = ["\x1E", "\x7E", "\x06", "\x13", "\x07", "\x66", "\x0E", "\x71"]
xor3 = ["\x17", "\x14", "\x1D", "\x70", "\x79", "\x67", "\x74", "\x33"]

result0 = '' 
result1 = ''
result2 = ''
result3 = ''

for i in range(8):
    result0 += chr(buffer0[i] ^ ord(xor0[i]))
    result1 += chr(buffer1[i] ^ ord(xor1[i]))
    result2 += chr(buffer2[i] ^ ord(xor2[i]))
    result3 += chr(buffer3[i] ^ ord(xor3[i]))

print(result0 + result1 + result2 + result3)