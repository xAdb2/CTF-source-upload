#!/usr/bin/env python3
"""
run_elf_with_pwntools.py

用法：
  # 從檔案讀 Base64（整個檔案是 base64）
  python3 run_elf_with_pwntools.py --b64-file payload.b64

  # 從命令列直接給 base64（注意 shell 長度限制）
  python3 run_elf_with_pwntools.py --b64 "BASE64_STRING_HERE"

  # 從 stdin 讀入 base64（例如 cat payload.b64 | python3 ...）
  cat payload.b64 | python3 run_elf_with_pwntools.py --from-stdin

說明：
- 會把 ELF 寫成臨時檔 /tmp/elf_<pid>_<rand> 並設為可執行。
- 使用 pwntools 的 process() 啟動，並呼叫 .interactive() 讓你與 ELF 互動。
- 執行結束會自動刪除臨時檔。
"""

import argparse
import base64
import os
import tempfile
import stat
import sys
import random
import string
from pathlib import Path

try:
    from pwn import process, context
except Exception as e:
    print("錯誤：無法 import pwntools。請先安裝 pwntools：")
    print("  pip install pwntools")
    raise

def read_b64_from_file(path: Path) -> bytes:
    return path.read_bytes()

def read_b64_from_stdin() -> bytes:
    return sys.stdin.buffer.read()

def decode_b64(data: bytes) -> bytes:
    # 忽略空白字元（換行等）
    try:
        # base64.b64decode 可以接受 bytes
        return base64.b64decode(b"".join(data.split()))
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

def make_tmp_elf_filename(prefix="elf_"):
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return Path(tempfile.gettempdir()) / f"{prefix}{os.getpid()}_{rand}"

def write_elf_and_chmod(binary: bytes, out_path: Path) -> None:
    out_path.write_bytes(binary)
    # chmod +x
    cur_mode = out_path.stat().st_mode
    out_path.chmod(cur_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

def main():
    parser = argparse.ArgumentParser(description="Decode base64 -> save ELF -> run with pwntools (interactive).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--b64-file", type=str, help="Path to file containing base64 (raw).")
    group.add_argument("--b64", type=str, help="Base64 string on command line (may be long).")
    group.add_argument("--from-stdin", action="store_true", help="Read base64 from stdin (binary-safe).")
    parser.add_argument("--out", type=str, default=None, help="Optional: specify output filename instead of temp file.")
    parser.add_argument("--arch", type=str, default=None, help="Optional: pwntools context.arch (e.g. amd64, i386).")
    parser.add_argument("--log-level", type=str, default="info", help="pwntools log level (debug/info).")
    args = parser.parse_args()

    # 取得 base64 bytes
    if args.b64_file:
        b64_raw = read_b64_from_file(Path(args.b64_file))
    elif args.b64:
        b64_raw = args.b64.encode()
    elif args.from_stdin:
        b64_raw = read_b64_from_stdin()
    else:
        parser.error("No base64 input provided.")

    # decode
    try:
        elf_bin = decode_b64(b64_raw)
    except ValueError as e:
        print("Base64 decode error:", e, file=sys.stderr)
        sys.exit(1)

    # 選擇檔名
    if args.out:
        out_path = Path(args.out)
    else:
        out_path = make_tmp_elf_filename()

    # 寫入並 chmod
    try:
        write_elf_and_chmod(elf_bin, out_path)
    except Exception as e:
        print(f"寫入檔案失敗: {e}", file=sys.stderr)
        sys.exit(1)

    # 設定 pwntools context（若提供）
    if args.arch:
        context.arch = args.arch
    context.log_level = args.log_level

    print(f"[+] 寫入 ELF 到: {out_path}")
    print("[+] 正在以 pwntools 啟動並切換到互動模式（Ctrl+D 或 程式結束 會回到此程式）")

    proc = None
    try:
        proc = process(str(out_path))
        # interactive 會把本地的 stdin/stdout 連到 process（可以輸入、看到即時輸出）
        proc.interactive()
        # 當用戶在 interactive 裡離開（Ctrl+D 或 process 結束）會回到這裡
    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt ，將嘗試終止 process")
        try:
            if proc:
                proc.close()
        except Exception:
            pass
    except Exception as e:
        print(f"[!] 啟動或互動過程發生錯誤: {e}", file=sys.stderr)
    finally:
        # 嘗試關閉 process
        try:
            if proc and proc.poll() is None:
                proc.close()
        except Exception:
            pass

        # 刪除臨時檔（如果是使用者指定 --out ，就保留）
        if not args.out:
            try:
                out_path.unlink()
                print(f"[+] 已刪除臨時檔: {out_path}")
            except Exception as e:
                print(f"[!] 無法刪除臨時檔 {out_path}: {e}", file=sys.stderr)
        else:
            print(f"[i] --out 指定輸出，檔案保留: {out_path}")

if __name__ == "__main__":
    main()
