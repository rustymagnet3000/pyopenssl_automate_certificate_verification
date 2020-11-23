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
    WantReadError
)
from support.CertCheck import CertificateChecker
from support.PyOpenSSLUnitTests import TestCertificateChecker


class OnlineCertVerify:
    def __init__(self):
        self.path_to_ca_certs = '/support/ca_files'
        self.verify_flags = 0x80000                     # partial Chain allowed
        self.context = self.set_context()
        self.socket = self.set_socket()
        self.tls_client = self.set_tls_client()

    @staticmethod
    def verify_cb(conn, cert, err_num, depth, ok):
        """
            Callback that holds the Cert Chain verify result
        """
        if not ok:
            print('[!]Certificate problem:', cert.get_subject().CN, 'chain depth', depth, 'verification failed:', err_num)
        return ok

    def set_tls_client(self):
        """
            After the socket and context have been defined, setup TLS client
        """
        tls_clt = Connection(self.context, self.socket)
        tls_clt.set_connect_state()  # set to work in client mode
        return tls_clt

    def set_socket(self):
        """
            Set the Socket, pre-handshake
        """
        sock = socket()
        sock.setblocking(True)
        sock.connect_ex(sock.getsockname())
        return sock

    def set_context(self):
        """
            Set the OpenSSL.context
        """
        con = Context(TLSv1_2_METHOD)
        con.set_options(OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_TLSv1)
        con.get_cert_store().set_flags(self.verify_flags)
        con.load_verify_locations(cafile=None, capath=Path(getcwd() + self.path_to_ca_certs).__bytes__())
        con.set_verify(VERIFY_PEER, OnlineCertVerify.verify_cb)
        return con


if __name__ == '__main__':
    print(CertificateChecker.openssl_version())

    hosts = ['stackoverflow.com', 'httpbin.org']
    verifier = OnlineCertVerify()
    port = 443

    for host in hosts:
        des = (hosts, port)

        try:
            print('[*]Connect issuing...')
            verifier.socket.connect(des)
            print('[*]connected: {0}\t{1}'.format(host, verifier.socket.getpeername()))
            verifier.tls_client.do_handshake()
            print('[*]Handshake succeeded...')
            CertificateChecker.print_cert_info(verifier.tls_client.get_peer_certificate())
        except WantReadError:
            print("[-]WantReadError")
        except:
            print("[!]general exception")
        finally:
            verifier.socket.close()


