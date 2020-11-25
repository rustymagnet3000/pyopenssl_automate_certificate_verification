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


class Results:
    certs = {}


class Verifier:
    results_list = []

    def __init__(self, ca_dir=Path(getcwd() + '/support/ca_files'),
                 c_rehash_loc=environ['HOME'] + '/openssl/bin/c_rehash'):
        self.cert_hash_count = 0
        self.path_to_ca_certs = Verifier.verify_ca_dir_and_files(ca_dir)
        self.path_to_c_rehash = Verifier.check_c_rehash_exists(c_rehash_loc)
        if self.path_to_ca_certs is None or self.path_to_c_rehash is None:
            return
        self.verify_flags = 0x80000  # partial Chain allowed
        self.context = self.set_context()
        self.run_c_rehash()

    @staticmethod
    def check_c_rehash_exists(c_rehash_location):
        """
            OpenSSL ships /bin/c_rehash.  Function to check it exists locally
        """
        if not exists(c_rehash_location):
            print('[!]Cannot find c_rehash at:\t{0}'.format(c_rehash_location))
            return None
        return c_rehash_location

    @staticmethod
    def verify_ca_dir_and_files(ca_dir):
        """
            Check CA directory exists
        """
        if not exists(ca_dir) and not isdir(ca_dir):
            print('[!]CA Directory of certificates not found:\t{0}'.format(ca_dir))
            return None
        return ca_dir

    def run_c_rehash(self):
        """
            rehash scans directories and calculates a hash value of each ".pem", ".crt", ".cer", or ".crl" file
        """
        process = subprocess.Popen([self.path_to_c_rehash, self.path_to_ca_certs],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if stderr.__len__() > 0 or stdout.__len__() == 0:
            print('[*]Error during c_rehash step:\t{0}'.format(stderr))
            return None
        print('[*]c_rehash:\t{0}'.format(stdout))

        for file in listdir(self.path_to_ca_certs):
            if file.endswith('.0'):
                self.cert_hash_count += 1
        if self.cert_hash_count > 0:
            print('[*]Found {0} certificate hash values in path:{1}'.format(self.cert_hash_count,
                                                                            self.path_to_ca_certs))

    @staticmethod
    def verify_cb(conn, cert, err_num, depth, ok):
        """
            Callback from OpenSSL. Invoked on each Certificate in Chain being checked.
        """
        b = {cert.get_subject().CN: ["pass" if ok else "fail", depth] }
        Verifier.results_list.append(b)
#        Verifier.results[depth, cert.get_subject().CN] = {'[!]verify failed:{}'.format(err_num)}

    #    Verifier.result_stack.index(cert.get_subject().CN).append
        return ok



    def set_context(self):
        """
            Set the OpenSSL.context
        """
        con = Context(TLSv1_2_METHOD)
        con.set_options(OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_TLSv1)
        con.get_cert_store().set_flags(self.verify_flags)
        con.load_verify_locations(cafile=None, capath=self.path_to_ca_certs.__bytes__())
        con.set_verify(VERIFY_PEER, Verifier.verify_cb)
        return con


if __name__ == '__main__':
    print(CertificateChecker.openssl_version())
    hosts = ['stackoverflow.com', 'httpbin.org']
    port = 443
    verifier = Verifier()
    if verifier.cert_hash_count == 0:
        exit(99)
    for host in hosts:
        des = (host, port)
        sock = socket()
        sock.setblocking(True)
        sock.connect_ex(sock.getsockname())
        tls_client = Connection(verifier.context, sock)
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
    for i in Verifier.results_list:
        print(i)
    print(Verifier.results_list)
