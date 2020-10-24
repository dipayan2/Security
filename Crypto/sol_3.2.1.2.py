from pymd5 import md5,padding
import sys
from urllib.parse import quote

query_file = str(sys.argv[1])
command_file = str(sys.argv[2])
outputFile = str(sys.argv[3])

myQuery = ''
myCommand = ''
myToken = ''
with open(query_file) as f:
    inpVal = f.read().strip()
    tempToken, myQuery = inpVal.split('&',1)
    myToken = tempToken.split('=')[1]
with open(command_file) as f:
    myCommand = f.read().strip()

length_of_m = 8+len(myQuery)
paddingString = padding(length_of_m*8)
stateCounter = (length_of_m + len(paddingString))*8
# print(stateCounter%512)

hasher = md5(state=myToken, count=stateCounter)
hasher.update(myCommand)
newToken = hasher.hexdigest()
# print(newToken)

newUrl = 'token='+str(newToken)+'&'+myQuery+quote(paddingString)+myCommand

#print("newUrl : ",newUrl)

fileOut = open(outputFile,'w')
fileOut.write(newUrl)
fileOut.close()