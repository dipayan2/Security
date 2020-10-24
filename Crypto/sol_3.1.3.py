from Crypto.Cipher import AES
import sys

if len(sys.argv) < 5:
    print("Insufficient arguements")
    exit()

cipher_file = str(sys.argv[1])
key_file = str(sys.argv[2])
iv_file = str(sys.argv[3])
output_file = str(sys.argv[4])

key=""
with open(key_file) as f:
    file_contents = f.read().strip()
    key = bytes.fromhex(file_contents)

iv=""
with open(iv_file) as f:
    file_contents = f.read().strip()
    iv = bytes.fromhex(file_contents)

ciphertext=""
with open(cipher_file) as f:
    file_contents = f.read().strip()
    ciphertext = bytes.fromhex(file_contents)

cipher = AES.new(key, AES.MODE_CBC, iv)
outText = cipher.decrypt(ciphertext)
outText = outText.decode()

file = open(output_file,'w')
file.write(outText)
file.close()