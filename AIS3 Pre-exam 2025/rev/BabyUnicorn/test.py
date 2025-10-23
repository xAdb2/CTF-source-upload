def idiv_32bit(eax: int, edx: int, divisor: int):
    """
    模擬 x86 的 IDIV 指令，針對有號整數除法： (EDX:EAX) / divisor

    :param eax: 32-bit 整數，代表低位
    :param edx: 32-bit 整數，代表高位
    :param divisor: 32-bit 有號整數除數
    :return: (quotient, remainder)
    """

    # 模擬 edx:eax 組合成 64-bit 被除數（有號）
    full_dividend = (edx << 32) | (eax & 0xFFFFFFFF)

    # 轉成有號整數（處理負數情況）
    if edx & 0x80000000:
        full_dividend -= (1 << 64)

    if divisor == 0:
        raise ZeroDivisionError("除數不能為 0")

    if divisor & 0x80000000:
        divisor -= (1 << 32)

    quotient = int(full_dividend // divisor)
    remainder = int(full_dividend % divisor)

    # 模擬 CPU 溢出檢查（IDIV 如果結果超過 32-bit 範圍會拋出 exception）
    if not -2**31 <= quotient <= 2**31 - 1:
        raise OverflowError("IDIV overflow: 商超出 32-bit 範圍")

    return quotient, remainder


# ✅ 測試例子
eax = 0x28
edx = 0x0
divisor = 0x2F

quot, rem = idiv_32bit(eax, edx, divisor)
print(f"EAX (商) = {quot}")
print(f"EDX (餘數) = {rem}")

GOAL =  [0x5a, 0x60, 0x61, 0xf, 0x8, 0x29, 0x42, 0x32, 0x25, 0x23, 0x42, 0x68, 0x4b, 0x41, 0x63, 0x55, 0x37, 0x43, 0x6a, 0x50, 0x40, 0x6f, 0x2e, 0x66, 0x49, 0x7f, 0x9, 0x66, 0x79, 0x7c, 0x37, 0x18, 0x5d, 0x35, 0x46, 0x41, 0x37, 0xf, 0x19, 0x1c, 0x30, 0x79, 0x29, 0x69, 0xa, 0x46, 0x3b]
print(len(GOAL))    