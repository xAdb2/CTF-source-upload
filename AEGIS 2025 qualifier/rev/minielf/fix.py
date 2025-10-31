#!/usr/bin/env python3
"""
emu_xor_debug.py
- like previous emulator but handles UC_ERR_INSN_INVALID by dumping RIP and nearby bytes + disasm
- supports --arch x86 (32-bit) or x86_64 (64-bit)
"""
import sys, base64, argparse
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

PAGE_SIZE = 0x1000
DEFAULT_BASE = 0x400000
STACK_SIZE = 0x20000
STACK_BASE = 0x0ff00000

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("b64", nargs="?", help="base64 string or use --file")
    p.add_argument("--file", "-f", help="read base64 from file")
    p.add_argument("--base", type=lambda x: int(x,0), default=DEFAULT_BASE)
    p.add_argument("--arch", choices=["x86","x86_64"], default="x86_64")
    p.add_argument("--pages", type=int, default=64)
    return p.parse_args()

def align_up(x,a=PAGE_SIZE): return ((x + a - 1)//a)*a
def decode_b64(s):
    try: return base64.b64decode(s)
    except Exception as e:
        print("base64 decode failed:", e); sys.exit(1)

def try_disasm(bytes_blob, addr, mode):
    md = Cs(CS_ARCH_X86, CS_MODE_64 if mode=="x86_64" else CS_MODE_32)
    md.detail = False
    return list(md.disasm(bytes_blob, addr))

def dump_memory_and_disasm(uc, rip, arch_mode):
    # print bytes around rip
    start = rip - 16
    if start < 0: start = 0
    try:
        data = uc.mem_read(start, 64)
    except UcError:
        # if memory isn't mapped near RIP, try read only from rip
        try:
            data = uc.mem_read(rip, 32)
            start = rip
        except UcError:
            print("[dump] cannot read memory around RIP (unmapped).")
            return
    hex_bytes = " ".join(f"{b:02x}" for b in data)
    print(f"[dump] memory @ 0x{start:x} (len {len(data)}):")
    print(hex_bytes)
    # disasm
    insns = try_disasm(bytes(data), start, arch_mode)
    if insns:
        print("[disasm] nearby instructions:")
        for i in insns[:12]:
            print(f"  0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
    else:
        print("[disasm] cannot disasm nearby bytes (likely data or wrong arch).")

def main():
    args = parse_args()
    if args.file:
        b64 = open(args.file,"r").read().strip()
    elif args.b64:
        b64 = args.b64.strip()
    else:
        print("provide base64 or --file"); sys.exit(1)
    code = decode_b64(b64)
    base = args.base
    code_size = len(code)
    map_size = align_up(code_size) + args.pages*PAGE_SIZE

    # select unicorn mode
    if args.arch == "x86_64":
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
    else:
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

    # map code+data region
    try:
        uc.mem_map(base, map_size, UC_PROT_ALL)
        uc.mem_write(base, code)
        print(f"[+] mapped {code_size} bytes to 0x{base:x}, region size {map_size}")
    except UcError as e:
        print("mem_map/write failed:", e); sys.exit(1)

    # stack
    try:
        uc.mem_map(STACK_BASE, align_up(STACK_SIZE), UC_PROT_ALL)
    except UcError as e:
        print("stack map failed:", e); sys.exit(1)

    if args.arch == "x86_64":
        uc.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE//2)
        uc.reg_write(UC_X86_REG_RBP, STACK_BASE + STACK_SIZE//2)
    else:
        uc.reg_write(UC_X86_REG_ESP, STACK_BASE + STACK_SIZE//2)
        uc.reg_write(UC_X86_REG_EBP, STACK_BASE + STACK_SIZE//2)

    # zero some regs
    regs64 = [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX]
    regs32 = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_EDX]
    for r in (regs64 if args.arch=="x86_64" else regs32):
        try:
            uc.reg_write(r, 0)
        except UcError:
            pass

    # Capstone for detecting target instruction
    cs_mode = "x86_64" if args.arch=="x86_64" else "x86"
    md = Cs(CS_ARCH_X86, CS_MODE_64 if cs_mode=="x86_64" else CS_MODE_32)
    md.detail = False

    def hook_code(uc_handle, address, size, user_data):
        # try to read and disasm current instruction
        try:
            bs = uc_handle.mem_read(address, size)
        except UcError:
            return
        insns = list(md.disasm(bytes(bs), address))
        if not insns:
            return
        insn = insns[0]
        if insn.mnemonic.lower() == "xor" and insn.op_str.replace(" ", "") == "rsi,rcx":
            # print regs
            try:
                if args.arch=="x86_64":
                    rip = uc_handle.reg_read(UC_X86_REG_RIP)
                    rcx = uc_handle.reg_read(UC_X86_REG_RCX)
                    rbx = uc_handle.reg_read(UC_X86_REG_RBX)
                    rdi = uc_handle.reg_read(UC_X86_REG_RDI)
                else:
                    rip = uc_handle.reg_read(UC_X86_REG_EIP)
                    rcx = uc_handle.reg_read(UC_X86_REG_ECX)
                    rbx = uc_handle.reg_read(UC_X86_REG_EBX)
                    rdi = uc_handle.reg_read(UC_X86_REG_EDI)
                print("==== Detected xor rsi, rcx ====")
                print(f"RIP=0x{rip:x}")
                print(f"RCX=0x{rcx:x} RBX=0x{rbx:x} RDI=0x{rdi:x}")
            except UcError:
                print("[hook] cannot read regs")
            uc_handle.emu_stop()

    # lazy map handler for unmapped mem
    def hook_mem_invalid(uc_handle, access, address, size, value, user_data):
        page = address & ~(PAGE_SIZE-1)
        try:
            uc_handle.mem_map(page, PAGE_SIZE, UC_PROT_ALL)
            uc_handle.mem_write(page, b"\x00"*PAGE_SIZE)
            print(f"[+] lazily mapped page 0x{page:x} for access at 0x{address:x}")
            return True
        except UcError as e:
            print("[!] lazy map failed:", e)
            return False

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_invalid)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
    uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)

    # run and handle invalid-instruction gracefully
    try:
        start = base
        end = base + map_size
        print(f"[+] starting emulation @0x{start:x}")
        uc.emu_start(start, end, timeout=0, count=1000000)
    except UcError as e:
        s = str(e)
        print("Emulation stopped with exception:", e)
        if "Invalid instruction" in s or "UC_ERR_INSN_INVALID" in s:
            # try to read RIP and dump memory + disasm
            try:
                rip = uc.reg_read(UC_X86_REG_RIP) if args.arch=="x86_64" else uc.reg_read(UC_X86_REG_EIP)
                print(f"[!] Invalid instruction at RIP=0x{rip:x}")
                dump_memory_and_disasm(uc, rip, cs_mode)
                print("\nHints:")
                print("- If the bytes look like ELF header (7f 45 4c 46), you're feeding an ELF; parse PT_LOAD segments instead.")
                print("- Try --arch x86 if you used x86_64 (or vice versa).")
                print("- Check whether the area is actually data, not code (strings, 0x00, etc).")
            except UcError:
                print("[!] cannot read RIP register (maybe unmapped).")
        else:
            # other errors: print and attempt to show RIP if possible
            try:
                rip = uc.reg_read(UC_X86_REG_RIP) if args.arch=="x86_64" else uc.reg_read(UC_X86_REG_EIP)
                print(f"[!] stopped near RIP=0x{rip:x}")
                dump_memory_and_disasm(uc, rip, cs_mode)
            except Exception:
                pass

if __name__ == "__main__":
    main()
