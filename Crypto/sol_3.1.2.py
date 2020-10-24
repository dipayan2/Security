import sys

if len(sys.argv) < 4:
    print("Insufficient arguements")
    exit()

cipher_file = str(sys.argv[1])
key_file = str(sys.argv[2])
output_file = str(sys.argv[3])

# Creating dictionary for the keys
initChar = 'A'
mapDic = {}
with open(key_file) as f:
    text = f.read().strip()
    for val in text:
        mapDic[val] = initChar
        initChar = chr(ord(initChar)+1)

# Decode the ciphertext
outText = ''
with open(cipher_file) as f:
    text = f.read().strip()
    for val in text:
        if val in mapDic:
            outText += mapDic[val]
        else:
            outText += val

# Write the result
file = open(output_file,'w')
file.write(outText)
file.close()