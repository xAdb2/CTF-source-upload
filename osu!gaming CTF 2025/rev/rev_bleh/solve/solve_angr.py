# solve_with_angr.py
import angr
import claripy
import sys

BINARY = "./bleh0"   # <- 改成你的二進位檔名（可執行檔）
L = 32

proj = angr.Project(BINARY, load_options={'auto_load_libs': False})

# 建立 symbolic stdin
flag_chars = [claripy.BVS(f'c{i}', 8) for i in range(L)]
flag = claripy.Concat(*flag_chars)
argv = [BINARY]
state = proj.factory.full_init_state(args=argv, stdin=flag)

# 限制輸入位元為可列印（可選，但比較常見）
for k in flag_chars:
    state.solver.add(k >= 0x00)
    state.solver.add(k <= 0xff)
    # 若你想只找 ascii printable:
    # state.solver.add(k >= 0x20)
    # state.solver.add(k <= 0x7e)

simgr = proj.factory.simulation_manager(state)

# 找到印出 "Nicely done" 的位置：我們可以用 find by stdout substring
def found_fn(s):
    try:
        out = s.posix.dumps(1)
        return b"Nicely done" in out
    except:
        return False

simgr.run(n=400)  # optional cap
found = None
for st in simgr.deadended + simgr.active + simgr.stashes.get('found', []):
    if found_fn(st):
        found = st
        break

# 如果 simgr 有提供 find API 可使用 (更直接):
# simgr.explore(find=lambda s: b"Nicely done" in s.posix.dumps(1), n=1)

if found is None:
    # 嘗試探勘（explore）
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=lambda s: b"Nicely done" in s.posix.dumps(1))
    if simgr.found:
        found = simgr.found[0]

if not found:
    print("沒有找到解。你可以加大探索深度或放寬約束。")
    sys.exit(1)

concrete = found.solver.eval(flag, cast_to=bytes)
print("找到輸入（raw bytes）：", concrete)
# 若是可列印 text，印出：
try:
    print("as text:", concrete.decode('latin-1'))
except:
    print("無法 decode 為可見文字，印 hex：", concrete.hex())

