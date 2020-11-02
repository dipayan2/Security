from Crypto.Util import number


def getStrongPrime(N, e):
    while True:
        prime = number.getPrime(N)
        if number.GCD(prime-1, e) == 1:
            return prime


num = getStrongPrime(64, 65537)
print(num, number.isPrime(num), number.GCD(num-1, 65537))
