import sys
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

if len(sys.argv) < 5:
    print("Insufficient arguements")
    exit()

cipher_file = str(sys.argv[1])
key_file    = str(sys.argv[2])
modulo_file = str(sys.argv[3])
output_file = str(sys.argv[4])

cipher_bytes=b""
cipher_whole_long=0
cipher_longs=[]
with open(cipher_file) as f:
    file_contents = f.read().strip()
    cipher_bytes = bytes.fromhex(file_contents)
    cipher_longs = [int(byte) for byte in cipher_bytes]
    cipher_whole_long = int.from_bytes(bytes.fromhex(file_contents), "big")

    # cipher_bytes = int(cipher_bytes,16)

key=b""
with open(key_file) as f:
    file_contents = f.read().strip()
    key = int.from_bytes(bytes.fromhex(file_contents), "big")
    
modulo=b""
with open(modulo_file) as f:
    file_contents = f.read().strip()
    modulo = int.from_bytes(bytes.fromhex(file_contents), "big")

impl = RSA.RSAImplementation(use_fast_math=False)
partial = impl.construct((modulo, 0))
partial.key.d = key

# enc_msg = map(bytes_to_long, cipher_bytes)
decrypt_first_byte = partial.key._decrypt(cipher_whole_long)
outPut = int.from_bytes(long_to_bytes(decrypt_first_byte), "big")
outFile = open(output_file,'w')
outFile.write(str(hex(outPut)))
outFile.close()
# print(int.from_bytes(long_to_bytes(decrypt_first_byte), "big"))
# decrypted = map(partial.key._decrypt, enc_msg)
# print(list(decrypted))

# print('decrypting: ')
# print(long_to_bytes(decrypted))
# for m in decrypted:

# rsa_key = RSA.construct((modulo, None, key))
# decrypted = rsa_key.decrypt(cipher_bytes)
