from Crypto.Cipher import AES
import sys

if len(sys.argv) < 3:
    print("Insufficient arguements")
    exit()

cipher_file = str(sys.argv[1])
# key_file = str(sys.argv[2])
# iv_file = str(sys.argv[3])
output_file = str(sys.argv[2])

# key=""
# with open(key_file) as f:
#     file_contents = f.read().strip()
#     key = bin(int(file_contents,16))
#     print(len(key))
#     key = int(key[2:],2).to_bytes(len(key) - 2,byteorder='big')
#     print(key)

keys = [int(i).to_bytes(32 ,byteorder='big') for i in range(32)]
iv=keys[0][:16]

ciphertext=""
with open(cipher_file) as f:
    file_contents = f.read().strip()
    ciphertext = bytes.fromhex(file_contents)

# Clean up the file in case it exists  
file = open(output_file, 'w')
file.write('')
file.close()
key = keys[21]
print(keys[21])
print(keys[21].hex())
# for key in keys[21:22]:
cipher = AES.new(key, AES.MODE_CBC, iv)
outText = cipher.decrypt(ciphertext)
# outText = outText
file = open(output_file,'a')
file.write(str(outText))
file.write('\n')
file.close()