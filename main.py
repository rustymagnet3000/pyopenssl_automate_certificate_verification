#!/usr/bin/python3
import OpenSSL.SSL
import cryptography
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import X509Store, X509StoreContext
from OpenSSL.crypto import FILETYPE_PEM
import unittest
from test_certs import good_leaf_cert_pem
from test_certs import bad_leaf_cert_pem
from test_certs import int_ca_cert_pem
from test_certs import root_ca_cert_pem


class CertificateChecker:
    def __init__(self, untrusted_cert_pem):
        root_cert = load_certificate(FILETYPE_PEM, root_ca_cert_pem)
        int_cert = load_certificate(FILETYPE_PEM, int_ca_cert_pem)
        untrusted_cert = load_certificate(FILETYPE_PEM, untrusted_cert_pem)
        trusted_certs = X509Store()
        trusted_certs.add_cert(root_cert)
        trusted_certs.add_cert(int_cert)

    def verify_cert(self):
        try:
            store_ctx = X509StoreContext(self.trusted_certs, self.untrusted_cert)
            store_ctx.verify_certificate()
        except:
            return False
        finally:
            return True

    @staticmethod
    def openssl_version():
        return "OpenSSL: {openssl}\ncryptography: {cryptography}".format(
            openssl=OpenSSL.SSL.SSLeay_version(OpenSSL.SSL.SSLEAY_VERSION),
            cryptography=cryptography.__version__)


class TestCertificateChecker(unittest.TestCase):
    def test_good_leaf_cert(self):
        c = CertificateChecker(good_leaf_cert_pem)
        self.assertTrue(c.verify_cert(), "Expected apple to be cut")

    def test_bad_leaf_cert(self):
        c = CertificateChecker(bad_leaf_cert_pem)
        self.assertFalse(c.verify_cert(), "Expected apple to be cut")

    def test_openssl_types(self):
        c = CertificateChecker(bad_leaf_cert_pem)
        self.assertTrue(isinstance(bad_leaf_cert, OpenSSL.crypto.X509))

if __name__ == '__main__':
    print(CertificateChecker.openssl_version())
    unittest.main()
