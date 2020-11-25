#!/usr/bin/python3
from pathlib import Path
import subprocess
from os import getcwd, listdir, environ
from os.path import isdir, exists
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
    results = {}

    def __init__(self, ca_dir=Path(getcwd() + '/support/ca_files'), c_rehash=environ['HOME'] + '/openssl/bin/c_rehash'):
        self.path_to_ca_certs = ca_dir
        self.path_to_c_rehash = c_rehash
        self.verify_flags = 0x80000                     # partial Chain allowed
        self.cert_hash_count = 0
        self.context = self.set_context()
        self.verify_ca_dir_and_files()

    def auto_run_c_rehash(self):
        """
            OpenSSL ships with /bin/c_rehash
            rehash scans directories and calculates a hash value of each ".pem", ".crt", ".cer", or ".crl" file
            Using a new Python import to do the same
        """
        if exists(self.path_to_c_rehash):
            process = subprocess.Popen(['~/openssl/bin/c_rehash', self.path_to_ca_certs],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            print(stdout, stderr)
        else:
            print('[!]Cannot find c_rehash at:{}'.format(self.path_to_c_rehash))
            return None

    def verify_ca_dir_and_files(self):
        """
            Check directory exists and contain symbolic link files from c_rehash
        """
        if exists(self.path_to_ca_certs) and isdir(self.path_to_ca_certs):
            self.auto_run_c_rehash()
            for file in listdir(self.path_to_ca_certs):
                if file.endswith('.0'):
                    self.cert_hash_count += 1
            if self.cert_hash_count > 0:
                print('[*]Found {0} certificate hash values in path:{1}'.format(self.cert_hash_count, self.path_to_ca_certs))

    @staticmethod
    def verify_cb(conn, cert, err_num, depth, ok):
        """
            Callback that holds the Cert Chain verify result
        """
        if ok:
            VerifySetup.results[cert.get_subject().CN] = 'VERIFIED'
        if not ok:
            VerifySetup.results[cert.get_subject().CN] = {'[!]verify failed:{1}'.format(depth, err_num)}
        return ok

    def set_context(self):
        """
            Set the OpenSSL.context
        """
        con = Context(TLSv1_2_METHOD)
        con.set_options(OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_TLSv1)
        con.get_cert_store().set_flags(self.verify_flags)
        con.load_verify_locations(cafile=None, capath=self.path_to_ca_certs.__bytes__())
        con.set_verify(VERIFY_PEER, VerifySetup.verify_cb)
        return con


if __name__ == '__main__':
    print(CertificateChecker.openssl_version())
    hosts = ['stackoverflow.com', 'httpbin.org']
    port = 443
    ver_setup = VerifySetup()

    # for host in hosts:
    #     des = (host, port)
    #     sock = socket()
    #     sock.setblocking(True)
    #     sock.connect_ex(sock.getsockname())
    #     tls_client = Connection(ver_setup.context, sock)
    #     tls_client.set_connect_state()  # set to work in client mode
    #     print('\n[*]Setting up socket to:{}'.format(host))
    #     sock.connect(des)
    #     print('[*]connected: {0}\t{1}'.format(host, sock.getpeername()))
    #     tls_client.do_handshake()
    #     try:
    #         print("")
    #     except WantReadError:
    #         print("[!]WantReadError")
    #     except Error as e:
    #         print("[!]OpenSSL.SSL.Error {0}", e)
    #     except:
    #         print("[!]general exception")
    #     finally:
    #         sock.close()
    # print(VerifySetup.results)

