import urllib.request, urllib.error
import sys

#hexFile = str(sys.argv[1])
hexFile = '3.2.3_ciphertext.hex'
def get_status(u):
    try:
        resp = urllib.request.urlopen(u)
        # print(resp.code,resp.read())
        return resp.code
    except urllib.error.HTTPError as e:
        return e.code
        # print(e, e.code)

# Get ciphertext from file
cipherText = ''
with open(hexFile) as f:
    cipherText = f.read().strip()

# If local testing, overrride the url header and cipherText
myUrlHeader = ''
mode='not local'
if mode == 'local':
    myUrlHeader = 'http://127.0.0.1:8081/mp3/test/'
    cipherText = 'bbf610b107317478eb41ee9a2a811d524f4d086a5535fc24e0356ca27b9d7006df293a48ce4df83b3c25802065ed320b'
else:
    myUrlHeader =  'http://192.17.103.142:8080/mp3/dipayan2/?'

cipherBlocks = [[int(cipherText[32*i+b*2:32*i+b*2+2],16) for b in range(16)] for i in range(0,len(cipherText)//32)]
globalPlainText = ''

def strip_padding(msg):
    padlen = 17 - ord(msg[-1])
    return msg[:-padlen]


def blockArrayToHexString(blocks):
    if len(blocks) == 0:
        return ''
    if not isinstance(blocks[0], list):
        blocks = [blocks]
    hexStr = ''
    for block in blocks:
        hexStr += ''.join([hex(val)[2:].zfill(2) for val in block])
    return hexStr
        
# print(blockArrayToHexString(cipherBlocks[0]))

def runGuesses(cipher):
    newUrl = myUrlHeader+cipher
    outResp = get_status(newUrl)
    return outResp


def solveBlock(cipherBlocks, i):
    localPText = '' # This is hex
    AESInvText = ''
    # lastByteMod = 0
    for l in range(15,-1,-1):
        cipherTextBlock = [ int(AESInvText[(15-j)*2:(16-j)*2],16)^(j) for j in range(15,l,-1) ]
        cipherPText = blockArrayToHexString(cipherTextBlock)
        print("cipher P Text",cipherPText)
        byteToModify = cipherBlocks[i-1][l]
        # lastByteMod = byteToModify
        print("bytetoModify : ", hex(byteToModify)[2:].zfill(2))

        print("deciphering : ", hex(cipherBlocks[i][l])[2:].zfill(2), i, l)
        modifiedbit = 0
        for bit in range(256):
            if False:
                continue
            else:
                urlCipher = blockArrayToHexString(cipherBlocks[:i-1])+blockArrayToHexString(cipherBlocks[i-1][:l])+hex(bit)[2:].zfill(2)+cipherPText+blockArrayToHexString(cipherBlocks[i])
                print("Bit :",bit," Cipher ",urlCipher)
                response = runGuesses(urlCipher)
                print("Bit :",bit,"response:", response)
                if response != 500:
                    # We good
                    modifiedbit = bit
                    break
                else:
                    continue
        # We have our successful guess in modifiedbit
        print("modifiedbit : ", modifiedbit)
        ptextByte = modifiedbit^cipherBlocks[i-1][l]^int('10',16)
        AESInvBit = modifiedbit^int('10',16)
        print("ptextByte : ", hex(ptextByte)[2:].zfill(2))
        localPText = hex(ptextByte)[2:].zfill(2) + localPText
        AESInvText = hex(AESInvBit)[2:].zfill(2)+AESInvText
        print("Current Ptext: ", bytes.fromhex(localPText).decode("ASCII"))
    # We have our localPText in hex
    textOutput = bytes.fromhex(localPText).decode("ASCII")
    return textOutput

def SolveAES(cipherBlocks):
    globalPlainText = ''
    for blockIdx in range(len(cipherBlocks)-1,0,-1):
        globalPlainText = solveBlock(cipherBlocks,blockIdx)+globalPlainText
    globalPlainText = strip_padding(globalPlainText)
    print("\nFinal Text: ",globalPlainText)

if __name__== '__main__':
    SolveAES(cipherBlocks)
