import subprocess
from os import listdir, remove
from os.path import isdir, exists, join
from support.YDCertChainLList import CertNode
from texttable import Texttable


class Verifier:
    certificate_chains = []

    def __init__(self, ca_dir, c_rehash_loc):
        self.cert_hash_count = 0
        self.path_to_ca_certs = ca_dir
        self.path_to_c_rehash = c_rehash_loc

    def __enter__(self):
        self.verify_ca_dir_and_files()
        self.check_c_rehash_exists()
        self.run_c_rehash()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for file in listdir(self.path_to_ca_certs):
            if file.endswith('.0') or file.endswith('.1'):
                remove(join(self.path_to_ca_certs, file))
        print("[*]clean-up.  Deleted all symbolic links.")

    def check_c_rehash_exists(self):
        """
            OpenSSL ships /bin/c_rehash.  Function to check it exists locally
        """
        if not exists(self.path_to_c_rehash):
            print('[!]Cannot find c_rehash at:\t{0}'.format(self.path_to_c_rehash))
            self.path_to_c_rehash = ''

    def verify_ca_dir_and_files(self):
        """
            Check CA directory exists. Input is a str ( not a Path ).
        """
        if not exists(self.path_to_ca_certs) and not isdir(self.path_to_ca_certs):
            print('[!]CA Directory of certificates not found:\t{0}'.format(self.path_to_ca_certs))
            self.path_to_ca_certs = ''

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

        for file in listdir(self.path_to_ca_certs):
            if file.endswith('.0'):
                self.cert_hash_count += 1

        print('[*]Creating symbolic links for OpenSSL\n[*]Certificates in Trust Store :{}'.format(self.cert_hash_count))

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

    @staticmethod
    def print_time_to_handshake():
        """
            Pretty print the hostname, time to tls-handshake
        """
        table = Texttable(max_width=130)
        table.set_cols_width([50, 10, 10, 40])
        table.set_deco(table.BORDER | Texttable.HEADER | Texttable.VLINES)
        table.header(['Hostname', 'Time', 'Cipher', 'TLS Protocol'])
        for chain in Verifier.certificate_chains:
            table.add_row([chain.name, chain.pretty_time(), chain.cipher_version, chain.tls_version])
        print("\n" + table.draw() + "\n")
