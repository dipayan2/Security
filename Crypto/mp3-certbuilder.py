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
                           u'unused01234567890123456789012345678901234567890123456789012345'),
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
    # p = 2359041718968085720059127955441196868435704273465233150674500925505347039698394131524512207421063070775797359926260772827243328665076534048694011283281
    # q = 4277117855595754632609876318936274146665524669510721482267176296893712862919250681377915113687051835640869565054182166205569575406142098389700265929479445999954031834526349913672071202099473007026331241965097236527522747311170626077355390041592628656643607026683245211419077697734408545648505723229996034977784370735945560440903584834392811331034008200144364313237276401521793751797083805710521277894861945283376449635431301930635527935314986895424387364531089915589
    # This is for certB
    p = 2573416838172085242353262527211940339899497152193141860487049736920999755186570315301112812483182062043235625395559722887238433950236806237013521933091
    q = 3920818154535983765364728894202613713123234016371719355740303598691565965388611837186495805207599069720214428461122579798508759872965219681888450901264328156270945507680632277288625424912362159920907332821700125581814341332652001737520502012435157905973263344997527705225464779891990261836994964320025932978893654652938881230131697897351082906273766523782269028128119012683641441678919362945716301643772624595260639223786186590293160350100150681995980978194235365159
    privkey, pubkey = make_privkey(p, q)
    cert = make_cert(netid, pubkey)
    print('md5 of cert.tbs_certificate_bytes:', hashlib.md5(
        cert.tbs_certificate_bytes).hexdigest())

    wholeTBS = cert.tbs_certificate_bytes
    prefixTBS = wholeTBS[:0x0100]
    print("Fraction of tbs prefix to total: ",
          len(prefixTBS), "/", len(wholeTBS))

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
