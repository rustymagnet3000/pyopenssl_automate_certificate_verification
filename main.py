#!/usr/bin/python3
import datetime

import OpenSSL

from OpenSSL.crypto import (
    X509Store,
    X509StoreContext,
    load_certificate,
    FILETYPE_PEM
)
from OpenSSL.SSL import (
    Connection,
    TLSv1_2_METHOD,
    OP_NO_SSLv2,
    OP_NO_SSLv3,
    OP_NO_TLSv1
)
from pathlib import Path
import os
import socket
import cryptography
import unittest
from test_certs import (
    good_leaf_cert_pem,
    bad_leaf_cert_pem,
    int_ca_cert_pem,
    root_ca_cert_pem
)


class CertificateChecker:
    def __init__(self, leaf_to_verify):
        self.trusted_certs = X509Store()
        self.load_trust_store()
        if isinstance(leaf_to_verify, OpenSSL.crypto.X509):
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
    def verify_cb(conn, cert, errnum, depth, ok):
        if not ok:
            print('certificate', cert.get_subject().CN, 'chain depth', depth, 'verification failed:', errnum)
        return ok

    @staticmethod
    def get_leaf_cert_from_host(host: str):
        """
            Create Stream socket and connects.  Blocking.  This is a connection oriented socket
            The SSLContext.wrap_socket()method returns an SSLSocket.
            upgrade the socket to TLS without any certificate verification, to obtain the certificate in bytes
        """
        ca_dir = Path(os.getcwd() + '/ca_files')
        context = OpenSSL.SSL.Context(TLSv1_2_METHOD)
        context.set_options(OP_NO_SSLv2)
        context.set_options(OP_NO_SSLv3)
        context.set_options(OP_NO_TLSv1)
        context.load_verify_locations(cafile=None, capath=ca_dir.__bytes__())
        context.set_verify(OpenSSL.SSL.VERIFY_PEER, CertificateChecker.verify_cb)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.settimeout(5)
        des = (host, 443)
        print('[*]Connect issued...')
        sock.connect(des)
        print('[*]connected: {0}\t{1}'.format(host, sock.getpeername()))
        tls_client = Connection(context, sock)                  # Connection object, using the given OpenSSL.SSL.Context
        tls_client.set_connect_state()                          # set to work in client mode
        tls_client.set_tlsext_host_name(host.encode('utf8'))    # Set value of servername extension for  client hello.
        try:

            tls_client.do_handshake()

            # usually called after: meth:`renegotiate` or one of: meth:`set_accept_state` or: meth:`set_connect_state`).

            print('[*]Connect succeeded...')
            CertificateChecker.print_cert_info(tls_client.get_peer_certificate())
            # ctx = ssl.create_default_context()
            # ctx.check_hostname = True
            # ctx.verify_mode = ssl.CERT_REQUIRED
            # self.context.set_verify(OpenSSL.SSL.VERIFY_PEER, self.verify_callback())
            OP_NO_SSLv2,
            OP_NO_SSLv3,
            OP_NO_TLSv1
            der_cert_bytes = sock.getpeercert(True)
            leaf_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert_bytes)
            return leaf_cert
        except OpenSSL.SSL.WantX509LookupError as e:
            print('[!]WantX509LookupError {0}'.format(e))
        except OpenSSL.SSL.WantReadError as e:
            print('[!]OpenSSL WantReadError {0}'.format(e))
        except OpenSSL.crypto.X509StoreContextError as e:
            print('[!]Certificate:\t{0}\t\tcode:{1}\t\t{2}'.format(e.certificate.get_subject().CN, e.args[0][0], e.args[0][2]))
            return None
        except:
            print("[!]general exception")
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
        check.trusted_certs.set_flags(0x80000)  # X509_V_FLAG_PARTIAL_CHAIN
        int_cert = load_certificate(FILETYPE_PEM, int_ca_cert_pem)
        check.trusted_certs.add_cert(int_cert)
        self.assertTrue(check.verify_cert(), "Expected OK. No Root CA. Int CA {0} . + flag for Partial Chain flag".format(int_cert))

    def test_openssl_types(self):
        check = CertificateChecker(bad_leaf_cert_pem)
        self.assertTrue(isinstance(check.trusted_certs, OpenSSL.crypto.X509Store))
        self.assertTrue(isinstance(check.untrusted_leaf, OpenSSL.crypto.X509))


if __name__ == '__main__':
   # print(CertificateChecker.openssl_version())
    CertificateChecker.get_leaf_cert_from_host('httpbin.org')
    # if untrusted_leaf is not None:
    #     checker = CertificateChecker(untrusted_leaf)
    #     print("[*]Verify {0} leaf.  Result:{1}".format(hostname, checker.verify_cert()))
