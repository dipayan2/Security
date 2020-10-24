import sys
inp_file = str(sys.argv[1])
out_file = str(sys.argv[2])

input_text = ''

with open(inp_file) as f:
    input_text = f.read().strip()
    # inp_hex = (file_content.encode()).hex()

def WHA(inp_str):
    outHash = '0'
    inp_hex = inp_str.encode().hex()
    # print(inp_hex)
    maskVal = '3fffffff'

    byteArr = [int(inp_hex[i:i+2],16) for i in range(0,len(inp_hex),2)]
    # print(byteArr)
    for byte in byteArr:
        inter_val = ((byte ^ int('CC',16) ) << 24) |  ((byte ^ int('33',16))<<16) | ((byte^int('AA',16))<<8)|((byte^int('55',16)))
        outHash = (int(outHash,16) & int(maskVal,16))+ (inter_val & int(maskVal,16))
        outHash = hex(outHash)[2:]

    return outHash

outVal = WHA(input_text)
outFile = open(out_file,'w')
outFile.write(str(outVal))
outFile.close()

## This is part to calculate the collision string

# print("Finding the collision string")
# matchHash = str(outVal)
# import string
# import random

# cnt = 0

# # while cnt < 100000000:

# inpStr = input_text[::-1]
# print(inpStr)
# hashVal = str(WHA(inpStr))
# if matchHash == hashVal:
#     print("**ANSWER** : ",inpStr)
# # cnt += 1
# # if cnt%100000==0:
# #     print("***NOT IT **",inpStr, " ", hashVal)
# #     print(cnt)

# print("End of the code")    