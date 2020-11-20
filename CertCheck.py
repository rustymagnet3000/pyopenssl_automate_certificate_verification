
from test_certs import (
    good_leaf_cert_pem,
    bad_leaf_cert_pem,
    int_ca_cert_pem,
    root_ca_cert_pem
)

from OpenSSL.crypto import (
    X509,
    X509Store,
    X509StoreContext,
    load_certificate,
    FILETYPE_PEM
)
from OpenSSL.SSL import (
    SSLEAY_VERSION,
    SSLeay_version
)
import datetime


class CertificateChecker:
    def __init__(self, leaf_to_verify):
        self.trusted_certs = X509Store()
        self.load_trust_store()
        if isinstance(leaf_to_verify, X509):
            self.untrusted_leaf = leaf_to_verify
        elif isinstance(leaf_to_verify, bytes):
            self.untrusted_leaf = load_certificate(FILETYPE_PEM, leaf_to_verify)

    def load_trust_store(self):
        print("[*]Constructing Trust Store")
        root_cert = load_certificate(FILETYPE_PEM, root_ca_cert_pem)
        int_cert = load_certificate(FILETYPE_PEM, int_ca_cert_pem)
        self.trusted_certs.add_cert(root_cert)
        self.trusted_certs.add_cert(int_cert)

    def verify_cert(self):
        try:
            store_ctx = X509StoreContext(self.trusted_certs, self.untrusted_leaf)
            store_ctx.verify_certificate()
            return True
        except OpenSSL.crypto.X509StoreContextError as e:
            print('[!]Certificate:\t{0}\t\tcode:{1}\t\t{2}'.format(e.certificate.get_subject().CN, e.args[0][0], e.args[0][2]))
            return False
        except:
            return False

    @staticmethod
    def print_cert_info(cert: X509):
        s = '''
        commonName: {commonname}
        issuer: {issuer}
        notBefore: {notbefore}
        notAfter:  {notafter}
        serial num: {serial_number}
        Expired: {expired}
        '''.format(
            commonname=cert.get_subject().CN,
            issuer=cert.get_issuer().CN,
            notbefore=CertificateChecker.pretty_date(cert.get_notBefore()),
            notafter=CertificateChecker.pretty_date(cert.get_notAfter()),
            serial_number=cert.get_serial_number(),
            expired=cert.has_expired()
        )
        print(s)

    @staticmethod
    def openssl_version():
        return "[*]OpenSSL: {openssl}".format(openssl=SSLeay_version(SSLEAY_VERSION))

    @staticmethod
    def pretty_date(date_from_cert: bytes):
        date = (datetime.datetime.strptime(date_from_cert.decode('ascii'), '%Y%m%d%H%M%SZ'))
        return(f"{date:%d-%b-%Y}")