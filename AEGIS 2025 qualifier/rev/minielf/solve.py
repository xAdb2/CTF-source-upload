# registers & constants (edit these if needed)
RBX = 0x84C1CFC66E309B25
RCX0 = 0x9B2AA49020162BE6
RDI0 = 0x00007FFCC9E9D492

C1 = 0xF07F1A70DC8ACE15
C2 = 0x8BAA813A1A6E9552
C3 = 0x0B4610BD3B3CE33D

# compute the required RSI (user input) so that final rsi == rbx
RSI_needed = RBX ^ RCX0 ^ C2

# simulate the code path to verify the two comparisons
rsi = RSI_needed
rcx = RCX0
rdi = RDI0

# xor rsi, rcx
rsi ^= rcx
# mov rcx, C1
rcx = C1
# xor rdi, rcx
rdi ^= rcx
# mov rcx, C2
rcx = C2
# xor rsi, rcx
rsi ^= rcx
# mov rcx, C3
rcx = C3
# xor rcx, rdi
rcx ^= rdi
# xor edi, edi  (doesn't affect rcx now; only zeroes RDI afterwards)
rdi = 0

ok1 = (rcx == RBX)
ok2 = (rsi == RBX)

print(f"RSI_needed = 0x{RSI_needed:016X} ({RSI_needed})")
print(f"Check1 rcx==rbx? {ok1}, rcx=0x{rcx:016X}, rbx=0x{RBX:016X}")
print(f"Check2 rsi==rbx? {ok2}, rsi=0x{rsi:016X}, rbx=0x{RBX:016X}")

# if Check1 fails, show the RDI value you'd need at entry
RDI_needed = C3 ^ C1 ^ RBX
print(f"RDI_needed_for_Check1 = 0x{RDI_needed:016X} ({RDI_needed})")