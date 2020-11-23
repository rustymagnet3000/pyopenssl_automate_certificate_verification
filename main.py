#!/usr/bin/python3
from pathlib import Path
from os import getcwd
from socket import socket
from OpenSSL.SSL import (
    Connection,
    TLSv1_2_METHOD,
    OP_NO_SSLv2,
    OP_NO_SSLv3,
    OP_NO_TLSv1,
    Context,
    VERIFY_PEER,
    WantReadError,
    Error
)
from support.CertCheck import CertificateChecker
from support.PyOpenSSLUnitTests import TestCertificateChecker


class VerifySetup:
    def __init__(self):
        self.path_to_ca_certs = '/support/ca_files'
        self.verify_flags = 0x80000                     # partial Chain allowed
        self.context = self.set_context()

    results = {}

    @staticmethod
    def verify_cb(conn, cert, err_num, depth, ok):
        """
            Callback that holds the Cert Chain verify result
        """
        if ok:
            VerifySetup.results = {cert.get_subject().CN,  'VERIFIED'}
        if not ok:
            VerifySetup.results = {'[!] + cert.get_subject().CN', 'chain depth{0}\tverify failed:{1}'.format(depth, err_num)}
        return ok

    def set_context(self):
        """
            Set the OpenSSL.context
        """
        con = Context(TLSv1_2_METHOD)
        con.set_options(OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_TLSv1)
        con.get_cert_store().set_flags(self.verify_flags)
        con.load_verify_locations(cafile=None, capath=Path(getcwd() + self.path_to_ca_certs).__bytes__())
        con.set_verify(VERIFY_PEER, VerifySetup.verify_cb)
        return con


if __name__ == '__main__':
    print(CertificateChecker.openssl_version())
    hosts = ['stackoverflow.com', 'httpbin.org']
    port = 443
    ver_setup = VerifySetup()


    for host in hosts:
        des = (host, port)
        sock = socket()
        sock.setblocking(True)
        sock.connect_ex(sock.getsockname())
        tls_client = Connection(ver_setup.context, sock)
        tls_client.set_connect_state()  # set to work in client mode
        print('\n[*]Setting up socket to:{}'.format(host))
        sock.connect(des)
        print('[*]connected: {0}\t{1}'.format(host, sock.getpeername()))
        tls_client.do_handshake()
        try:
            print("")
        except WantReadError:
            print("[!]WantReadError")
        except Error as e:
            print("[!]OpenSSL.SSL.Error {0}", e)
        except:
            print("[!]general exception")
        finally:
            sock.close()
    print(VerifySetup.results)

