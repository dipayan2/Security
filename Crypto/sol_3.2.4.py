import sys
import math
from Crypto.Util import number
from Crypto.PublicKey import RSA
from pbp import *



def readInputFiles():
    inpFile = 'moduli.hex'
    ReadNvalues = []
    with open(inpFile) as f:
        for line in f.readlines():
            # print(line)
            ReadNvalues.append(line.strip())


    # convert to int
    NModulo = []
    for val in ReadNvalues:
        # print(val)
        NModulo.append(int(val,16))
    return NModulo

def readMessageFile():
    inpFile = '3.2.4_ciphertext.enc.asc'
    cipherText = ''
    with open(inpFile) as f:
        cipherText = f.read().strip()
    return cipherText

def get_d(p, q, e):
    totient = (p-1)*(q-1)
    return number.inverse(e,totient)

# Reference: https://facthacks.cr.yp.to/product.html
def prod(X):
    if len(X) == 0:
        return 1
    val = 1
    for v in X:
        val *= v
    return val

def producttree(X):
    result = [X]
    while len(X) > 1:
        X = [prod(X[i*2:(i+1)*2]) for i in range(int((len(X)+1)/2))]
        result.append(X)
    return result

# def QuasilinearGCD(NArr):
#     P = producttree(NArr)[-1][0]

#     NarrSquaredList = [val*val for val in NArr]

#     RemProdTree = producttree(NarrSquaredList)
    

def batchgcd_faster(X):
    print("Started Calculating GCD.....")
    prods = producttree(X)
    R = prods.pop()
    while prods:
        X = prods.pop()
        R = [R[i//2] % X[i]**2 for i in range(len(X))]
    return [math.gcd(r//n,n) for r,n in zip(R,X)]


def findPQ_Pair(NArr, PArr, e_pub):
    print("Finding PQ pairs.....")
    P_QPair = []
    for i in range(len(NArr)):
        nVal = NArr[i]
        pVal = PArr[i]
        if nVal==pVal or pVal == 1:
            continue
        else:
            qVal = nVal//pVal
            mydEst = get_d(pVal,qVal,e_pub)
            P_QPair.append((nVal,mydEst))
    return P_QPair
            
    # For a

# def RSADecrypt(msg, Nmod, keyD):
#     impl = RSA.RSAImplementation(use_fast_math=False)
#     partial = impl.construct((NMod, 0))
#     partial.key.d = keyD
#     decrypted = partial.key._decrypt(cipher_whole_long)
#     outText = decrypted.hex().decode("ASCII")
#     return outText



if __name__ == '__main__':
    NModulo = readInputFiles()
    cipherText = readMessageFile()
    print("Cipher : ", cipherText)
    e_pub = 65537
    results = batchgcd_faster(NModulo)
    possible_KeyVal = findPQ_Pair(NModulo,results,e_pub)
    print("Possible Keys :",possible_KeyVal)
    print("Decrypting.....")
    for val in possible_KeyVal:
        nmod,dpriv = val
        myKey = RSA.construct((nmod,e_pub,dpriv))
        pText = decrypt(myKey,cipherText)
        print(pText)
        print("\n")

    
