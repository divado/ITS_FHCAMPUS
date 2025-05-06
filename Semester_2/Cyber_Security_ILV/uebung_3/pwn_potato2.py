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
break login2.c:32
continue
''')

print(p.recvuntil(b"cmd> "))
p.sendline(b"login")
# test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> "))

p.interactive()
