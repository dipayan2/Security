from Crypto.Util import number


def getCRT(b1, b2, p1, p2):
    N = p1 * p2
    invOne = number.inverse(p2, p1)
    invTwo = number.inverse(p1, p2)
    return -(b1 * invOne * p2 + b2 * invTwo * p1) % N


def getStrongPrime(N, e):
    while True:
        prime = number.getPrime(N)
        if number.GCD(prime-1, e) == 1:
            return prime


pA = 2736205936998955007437892415960146471770722873817241200719211375175733535276871908736203688240980374459982272143050387856312267325635564242549015420661
qA = 3810579579515027202707082020251218382072320920752984027932646164627628848926483877930951971801982866203302894837487576883042292751649284486762526685338656083075853064035159836379951828515165611701047437143419550584655988267561519959632935545919928433879483148063613525035827771346449378523465372149715170247106319325044801619456296398060264423278332202944226078298261346748779177974497557084521789146201337306964790845135898955689927775919359035973928891526242054763

pB = 2279667056371984928129597267081385668549055705744058083215704388642081587906114443015024749200598489455746289461608953211794862986360784454622403266723
qB = 4573707568275114251760760009336656690876872177887837126073333406162143097430391027580224486714219031927143121050021311547067572510859965992840273649816573679203054350075770520057338225557135586702305743698358239244058805578131043369617325687122232588942657108987387719805414297304190160092806067276399041798165105326895756860352470820543970712495097638881727177391054428134782315166227473074784445002446257624530193425748651071572779423867949912440817918455991254893

with open('sol_3.2.5_factorsA.hex', 'w') as f:
    f.write(hex(pA)[2:]+'\n'+hex(qA)[2:])

with open('sol_3.2.5_factorsB.hex', 'w') as f:
    f.write(hex(pB)[2:]+'\n'+hex(qB)[2:])


b1 = 0
b2 = 0

with open('test_cert_coll1', 'rb') as f:
    fnumBytes = f.read()
    fnum = fnumBytes[256:]
    b1 = number.bytes_to_long(fnum)
    assert number.size(b1) == 1023
    print(number.size(b1))

with open('test_cert_coll2', 'rb') as f:
    fnumBytes = f.read()
    fnum = fnumBytes[256:]
    b2 = number.bytes_to_long(fnum)
    assert number.size(b2) == 1023
    print(number.size(b2))

N = 500
e = 65537
p1 = 0
p2 = 0
b = 0
b0 = 0
q1 = 0
q2 = 0
flag = False
while not flag:
    p1 = getStrongPrime(N, e)
    p2 = getStrongPrime(N, e)
    assert number.isPrime(p1) == True
    assert number.isPrime(p2) == True

    b0 = getCRT(b1 << 1024, b2 << 1024, p1, p2)
    temp1 = ((b1 << 1024) + b0)
    temp2 = ((b2 << 1024) + b0)
    assert b0 < p1*p2
    assert b0 > 0
    assert ((b1 << 1024) + b0) % p1 == 0
    assert ((b2 << 1024) + b0) % p2 == 0
    # print("p1 :", temp1 % p1, " \np2 :", temp2 % p2)

    k = 0
    while True:
        b = b0+(k*p1*p2)
        k += 1
        if number.size(b) >= 1024:
            print("b is 1024+ bits, restarting ....")
            break
        temp1 = ((b1 << 1024)+b)
        temp2 = ((b2 << 1024)+b)
        if temp1 % p1 != 0 or temp2 % p2 != 0:
            print("Incorrect mod for temps")
            continue
        q1 = temp1//p1
        q2 = temp2//p2

        if k % 10000 == 0:
            print("k: ", k)
            print("sizeof(b): ", number.size(b))
        # Check if q1, q2 prime
        valQ1 = number.isPrime(q1)
        valQ2 = number.isPrime(q2)
        if not (valQ1 and valQ2):
            continue
        print("First check passed")
        # Check if q1, q2 coprime to e
        valQ1 = (number.GCD(e, q1-1) == 1)
        valQ2 = (number.GCD(e, q2-1) == 1)
        if not (valQ1 and valQ2):
            continue
        # SUccess, stop
        print("Success")
        flag = True
        break

n1 = (b1 << 1024) + b
n2 = (b2 << 1024) + b
print("n1", n1, ", Length:", number.size(n1))
print("n2", n2, ", Length:", number.size(n2))
print("p1", p1, ", Length:", number.size(p1))
print("p2", p2, ", Length:", number.size(p2))
print("q1", q1, ", Length:", number.size(q1))
print("q2", q2, ", Length:", number.size(q2))

with open('test_cert_n1', 'w') as f:
    myStr = "n1 : "+str(n1)+"\n"+"p1 : "+str(p1)+"\nq1 :"+str(q1)
    f.write(myStr)

with open('test_cert_n2', 'w') as f:
    myStr = "n2 : "+str(n2)+"\n"+"p2 : "+str(p2)+"\nq2 :"+str(q2)
    f.write(myStr)
