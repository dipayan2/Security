from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Util import number
import datetime
import hashlib

# Utility to make a cryptography.x509 RSA key object from p and q


def make_privkey(p, q, e=65537):
    n = p*q
    d = number.inverse(e, (p-1)*(q-1))
    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(e, p)
    dmq1 = rsa.rsa_crt_dmq1(e, q)
    pub = rsa.RSAPublicNumbers(e, n)
    priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
    pubkey = pub.public_key(default_backend())
    privkey = priv.private_key(default_backend())
    return privkey, pubkey


# The ECE422 CA Key! Your cert must be signed with this.
ECE422_CA_KEY, _ = make_privkey(10079837932680313890725674772329055312250162830693868271013434682662268814922750963675856567706681171296108872827833356591812054395386958035290562247234129,
                                13163651464911583997026492881858274788486668578223035498305816909362511746924643587136062739021191348507041268931762911905682994080218247441199975205717651)

# Skeleton for building a certificate. We will require the following:
# - COMMON_NAME matches your netid.
# - COUNTRY_NAME must be US
# - STATE_OR_PROVINCE_NAME must be Illinois
# - issuer COMMON_NAME must be ece422
# - 'not_valid_before' date must must be March 1
# - 'not_valid_after'  date must must be March 27
# Other fields (such as pseudonym) can be whatever you want, we won't check them


def make_cert(netid, pubkey, ca_key=ECE422_CA_KEY, serial=x509.random_serial_number()):
    serial = 619896898465676799222673698197894680027116984392
    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(datetime.datetime(2017, 3, 1))
    builder = builder.not_valid_after(datetime.datetime(2017, 3, 27))
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, str(netid)),
        x509.NameAttribute(NameOID.PSEUDONYM,
                           u'unused012345678901234567890123456789012345678901234567890123456'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'ece422'),
    ]))
    print("Serial : ", serial)
    builder = builder.serial_number(serial)
    builder = builder.public_key(pubkey)
    cert = builder.sign(private_key=ECE422_CA_KEY,
                        algorithm=hashes.MD5(), backend=default_backend())
    return cert


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print('usage: python mp3-certbuilder <netid> <outfile.cer>')
        sys.exit(1)
    netid = sys.argv[1]
    outfile = sys.argv[2]
    # p = number.getPrime(1024)
    # q = number.getPrime(1024)
    # This is for certA
    # p = 2736205936998955007437892415960146471770722873817241200719211375175733535276871908736203688240980374459982272143050387856312267325635564242549015420661
    # q = 3810579579515027202707082020251218382072320920752984027932646164627628848926483877930951971801982866203302894837487576883042292751649284486762526685338656083075853064035159836379951828515165611701047437143419550584655988267561519959632935545919928433879483148063613525035827771346449378523465372149715170247106319325044801619456296398060264423278332202944226078298261346748779177974497557084521789146201337306964790845135898955689927775919359035973928891526242054763
    # This is for certB
    p = 2279667056371984928129597267081385668549055705744058083215704388642081587906114443015024749200598489455746289461608953211794862986360784454622403266723
    q = 4573707568275114251760760009336656690876872177887837126073333406162143097430391027580224486714219031927143121050021311547067572510859965992840273649816573679203054350075770520057338225557135586702305743698358239244058805578131043369617325687122232588942657108987387719805414297304190160092806067276399041798165105326895756860352470820543970712495097638881727177391054428134782315166227473074784445002446257624530193425748651071572779423867949912440817918455991254893
    privkey, pubkey = make_privkey(p, q)
    cert = make_cert(netid, pubkey)
    print('md5 of cert.tbs_certificate_bytes:', hashlib.md5(
        cert.tbs_certificate_bytes).hexdigest())

    n = p*q
    print(hex(n))

    wholeTBS = cert.tbs_certificate_bytes
    prefixTBS = wholeTBS[:0x0100]
    print("Fraction of tbs prefix to total: ",
          len(prefixTBS), "/", len(wholeTBS))

    print(wholeTBS)
    print()
    print(prefixTBS)

    # Write TBS bytes so that they can be used by fastcoll
    with open(outfile+"_tbs", 'wb') as f:
        f.write(wholeTBS)
    with open(outfile+"_tbs_prefix", 'wb') as f:
        f.write(prefixTBS)

    # We will check that your certificate is DER encoded
    # We will validate it with the following command:
    #    openssl x509 -in {yourcertificate.cer} -inform der -text -noout
    with open(outfile, 'wb') as f:
        f.write(cert.public_bytes(Encoding.DER))
    print('try the following command: openssl x509 -in %s -inform der -text -noout' % outfile)
