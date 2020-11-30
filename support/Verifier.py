#!/usr/bin/python3
from pathlib import Path
import subprocess
from os import getcwd, listdir, environ
from os.path import isdir, exists
from OpenSSL.SSL import (
    TLSv1_2_METHOD,
    OP_NO_SSLv2,
    OP_NO_SSLv3,
    OP_NO_TLSv1,
    Context,
    VERIFY_PEER
)
from support.CertChainLList import CertNode, SinglyLinkedList


class Verifier:
    certificate_chains = []

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
            print('[!]Error during c_rehash step:\t{0}'.format(stderr))
            return None
        print('[*]Creating symbolic links for OpenSSL')

        for file in listdir(self.path_to_ca_certs):
            if file.endswith('.0'):
                self.cert_hash_count += 1

    @staticmethod
    def verify_cb(conn, cert, err_num, depth, ok):
        """
            Callback from OpenSSL. Invoked on each Certificate in Chain being checked.
            The code loops through a List of Linked Lists. These Linked Lists represent each Certificate Chain.
            if it finds the Linked List a matching servername it wants to adds Certs to that chain
            If there is no Head, set it with Cert being verified ( as OpenSSL starts at the top of hierarchy )
            If not, add it at the end of the Linked List
            Break to avoid going through all the other Linked Lists, if the Cert was added
        """
        result = "pass" if ok else "fail:{}".format(err_num)

        for chain in Verifier.certificate_chains:
            if (bytes(chain.name, 'utf-8')) in conn.get_servername():
                cert = CertNode(result, depth, cert.get_subject().CN)
                if chain.head_val is None:
                    chain.head_val = cert
                    break
                else:
                    chain.at_end(cert)
                    break
        return ok

    def set_context(self):
        """
            Set the OpenSSL.context. Notice it sets a flag ont the Cert Store associated to the Context
        """
        con = Context(TLSv1_2_METHOD)
        con.set_options(OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_TLSv1)
        con.get_cert_store().set_flags(self.verify_flags)
        con.load_verify_locations(cafile=None, capath=self.path_to_ca_certs.__bytes__())
        con.set_verify(VERIFY_PEER, Verifier.verify_cb)
        return con
