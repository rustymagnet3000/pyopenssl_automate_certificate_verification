#!/usr/bin/python3
import datetime
import OpenSSL.SSL
from OpenSSL.crypto import X509Store, X509StoreContext, load_certificate, FILETYPE_PEM
from pathlib import Path
import socket
import ssl
import cryptography
import unittest
from test_certs import good_leaf_cert_pem
from test_certs import bad_leaf_cert_pem
from test_certs import int_ca_cert_pem
from test_certs import root_ca_cert_pem


class CertificateChecker:
    def __init__(self, untrusted_leaf):
        self.trusted_certs = X509Store()
        self.load_trust_store()
        if isinstance(untrusted_leaf, OpenSSL.crypto.X509):
            self.untrusted_leaf = untrusted_leaf
        elif isinstance(untrusted_leaf, bytes):
            self.untrusted_leaf = load_certificate(FILETYPE_PEM, untrusted_leaf)

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
    def print_cert_info(cert: OpenSSL.crypto.X509):
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
    def get_leaf_cert_from_host(hostname: str):
        '''
            Create Stream socket and connects.  Blocking.  This is a connection oriented socket
            The SSLContext.wrap_socket()method returns an SSLSocket.
            upgrade the socket to TLS without any certificate verification, to obtain the certificate in bytes
        '''
        #
        dest = (hostname, 443)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(dest)

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            sock = ctx.wrap_socket(sock, server_hostname=dest[0])
            der_cert_bytes = sock.getpeercert(True)
            leaf_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert_bytes)
            return leaf_cert
        except:
            return None
        finally:
            sock.close()

    @staticmethod
    def openssl_version():
        return "OpenSSL: {openssl}\ncryptography: {cryptography}".format(
            openssl=OpenSSL.SSL.SSLeay_version(OpenSSL.SSL.SSLEAY_VERSION),
            cryptography=cryptography.__version__)

    @staticmethod
    def pretty_date(date_from_cert: bytes):
        date = (datetime.datetime.strptime(date_from_cert.decode('ascii'), '%Y%m%d%H%M%SZ'))
        return(f"{date:%d-%b-%Y}")


class TestCertificateChecker(unittest.TestCase):
    def test_good_leaf_cert(self):
        check = CertificateChecker(good_leaf_cert_pem)
        self.assertTrue(check.verify_cert(), "Expected good leaf to Verify")

    def test_bad_leaf_cert(self):
        check = CertificateChecker(bad_leaf_cert_pem)
        self.assertFalse(check.verify_cert(), "Expected bad leaf to fail Verify")

    def test_no_int_ca_in_trust_store(self):
        check = CertificateChecker(good_leaf_cert_pem)
        check.trusted_certs = X509Store()       # re-init Trust Store
        root_cert = load_certificate(FILETYPE_PEM, root_ca_cert_pem)
        check.trusted_certs.add_cert(root_cert)
        self.assertFalse(check.verify_cert(), "Expected to fail verify, as Int CA was removed")

    def test_partial_chain_allowed(self):
        check = CertificateChecker(good_leaf_cert_pem)
        check.trusted_certs = X509Store()       # re-init Trust Store
        check.trusted_certs.set_flags(0x80000)
        int_cert = load_certificate(FILETYPE_PEM, int_ca_cert_pem)
        check.trusted_certs.add_cert(int_cert)
        self.assertTrue(check.verify_cert(), "Expected OK. No Root CA. Int CA {0} . + flag for Partial Chain flag".format(int_cert))

    def test_openssl_types(self):
        check = CertificateChecker(bad_leaf_cert_pem)
        self.assertTrue(isinstance(check.trusted_certs, OpenSSL.crypto.X509Store))
        self.assertTrue(isinstance(check.untrusted_leaf, OpenSSL.crypto.X509))


if __name__ == '__main__':

    tests = TestCertificateChecker()
    unittest.main(tests.test_partial_chain_allowed())
