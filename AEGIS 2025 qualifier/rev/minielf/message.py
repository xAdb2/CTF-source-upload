#!/usr/bin/env python3
# emu_xor_hook.py
# 用法:
#   python emu_xor_hook.py <base64string>
# 或把 base64 放在檔案裡:
#   python emu_xor_hook.py --file payload.b64

import sys
import base64
import argparse
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# 一些模擬配置常數
MAP_ADDR = 0x1000000        # 將機器碼映射到這個位址 (1MB)
STACK_ADDR = 0x2000000      # stack base (2MB)
STACK_SIZE = 0x2000         # 8KB stack
MAX_INSN_COUNT = 100000     # 防止無窮迴圈的執行上限

def parse_args():
    p = argparse.ArgumentParser(description="Unicorn x86-64 emulator: decode base64 and hook on 'xor rsi, rcx'")
    p.add_argument("b64", nargs="?", help="base64 string containing raw x86-64 machine code")
    p.add_argument("--file", "-f", help="read base64 from file (plain text)")
    return p.parse_args()

def decode_base64_input(b64text):
    try:
        return base64.b64decode(b64text)
    except Exception as e:
        print("base64 decode failed:", e)
        sys.exit(1)

def align_up(x, a):
    return (x + a - 1) // a * a

def main():
    args = parse_args()
    if args.file:
        with open(args.file, "r") as fh:
            b64text = fh.read().strip()
    elif args.b64:
        b64text = args.b64.strip()
    else:
        print("請提供 base64 字串或使用 --file 指定檔案。")
        sys.exit(1)

    code = decode_base64_input(b64text)
    if len(code) == 0:
        print("解碼後的機器碼長度為 0，結束。")
        sys.exit(1)

    # 初始化 Unicorn x86_64
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    # 分配記憶體 (code + stack)，簡單地 align 到 page (0x1000)
    PAGE_SIZE = 0x1000
    code_size = len(code)
    map_size = align_up(code_size, PAGE_SIZE)
    uc.mem_map(MAP_ADDR, map_size, UC_PROT_ALL)
    uc.mem_write(MAP_ADDR, code)

    # stack
    uc.mem_map(STACK_ADDR, align_up(STACK_SIZE, PAGE_SIZE), UC_PROT_ALL)
    initial_rsp = STACK_ADDR + STACK_SIZE // 2  # 放在 stack 範圍中間
    uc.reg_write(UC_X86_REG_RSP, initial_rsp)

    # 初始化其他寄存器（可視需求改動）
    uc.reg_write(UC_X86_REG_RBP, 0x0)
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RBX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, 0x0)
    uc.reg_write(UC_X86_REG_RDI, 0x0)
    uc.reg_write(UC_X86_REG_RSI, 0x0)

    # Capstone 用於反組譯單一指令
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    # flag 讓 hook 停止執行
    triggered = {"hit": False}

    # 指令 hook
    def hook_code(uc_handle, address, size, user_data):
        # 讀取該指令的位元組
        try:
            code_bytes = uc_handle.mem_read(address, size)
        except Exception as e:
            print(f"[hook] mem_read failed at 0x{address:x}, size {size}: {e}")
            return

        # 用 capstone 反組譯單條指令（通常 size 就是一條指令長度）
        insns = list(md.disasm(bytes(code_bytes), address))
        if not insns:
            return
        insn = insns[0]
        # 比對精確的文字：mnemonic + op_str
        insn_text = f"{insn.mnemonic} {insn.op_str}".strip()
        # 也可用 lower() 以防大小寫差異
        if insn.mnemonic.lower() == "xor" and insn.op_str.replace(" ", "") == "rsi,rcx":
            # 讀出我們要的寄存器
            rcx = uc_handle.reg_read(UC_X86_REG_RCX)
            rbx = uc_handle.reg_read(UC_X86_REG_RBX)
            rdi = uc_handle.reg_read(UC_X86_REG_RDI)
            rip = uc_handle.reg_read(UC_X86_REG_RIP)
            print("==== Detected target instruction 'xor rsi, rcx' ====")
            print(f"RIP = 0x{rip:x}")
            print(f"RCX = 0x{rcx:x} ({rcx})")
            print(f"RBX = 0x{rbx:x} ({rbx})")
            print(f"RDI = 0x{rdi:x} ({rdi})")
            triggered["hit"] = True
            # 停止模擬
            uc_handle.emu_stop()

    # 註冊 hook：每條指令進來就呼叫
    uc.hook_add(UC_HOOK_CODE, hook_code)

    # 開始模擬，從 MAP_ADDR 執行到 MAP_ADDR + code_size（如果沒有提前 stop）
    try:
        uc.emu_start(MAP_ADDR, MAP_ADDR + code_size, timeout=0, count=MAX_INSN_COUNT)
    except Exception as e:
        # 如果發生未捕捉的錯誤（例如執行到 unmapped memory），會拋例外
        if not triggered["hit"]:
            print("Emulation stopped with exception:", e)

    if not triggered["hit"]:
        print("模擬結束但未遇到 'xor rsi, rcx' 指令。")

if __name__ == "__main__":
    main()
