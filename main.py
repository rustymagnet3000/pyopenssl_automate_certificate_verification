#!/usr/bin/python3
import time
from os import getcwd, environ
from OpenSSL.SSL import (
    Connection,
    Error,
    WantReadError
)
import argparse
from support.SocketSetup import SocketSetup
from support.Verifier import Verifier
from support.HostNameClean import HostNameCleaner
from support.CertCheck import CertificateChecker
from support.CertChainLList import SinglyLinkedList


parser = argparse.ArgumentParser(description="PyOpenSSL")

parser.add_argument(
    '--hostnames-file',
    '-f',
    help='Path to text file that includes hostnames to check',
    type=argparse.FileType('r', encoding='UTF-8'),
    required=True)

parser.add_argument(
    "-r",
    "--rehash-path",
    help='Path to OpenSSL\'s c_rehash tool. This generates the symbolic required for OpenSSL\'s Verify() to work'
         'If you don\'t include this value, it will default to ~/openssl/bin',
    default=environ['HOME'] + '/openssl/bin/c_rehash',
    required=False)


parser.add_argument(
    "-c",
    "--certs-path",
    help='Path to directory of Root and Intermediate Cert Authority certificates',
    default=getcwd() + '/support/ca_files',
    required=False)

args = parser.parse_args()


if __name__ == '__main__':
    CertificateChecker.openssl_version()

    with args.hostnames_file as file:
        sanitized_hosts = HostNameCleaner(file)
    hosts = sanitized_hosts.hostnames

    verifier = Verifier(ca_dir=args.certs_path, c_rehash_loc=args.rehash_path)
    assert (verifier.cert_hash_count > 0)

    for host in hosts:
        s = SocketSetup(host)
        s.connect_socket()

    SocketSetup.print_all_connections()
    SocketSetup.clean_up()
    # for host in hosts:

    #     tls_client = Connection(verifier.context, s.sock)
    #     tls_client.set_tlsext_host_name(bytes(host, 'utf-8'))   # Ensures ServerName when Verify callback invokes
    #     cert_chain = SinglyLinkedList(host)
    #     Verifier.certificate_chains.append(cert_chain)
    #     cert_chain.start_time = time.time()
    #
    #     try:
    #         tls_client.set_connect_state()  # set to work in client mode
    #         # tls_client.do_handshake()
    #
    #     except WantReadError:
    #         print("[!]WantReadError")
    #     except Error as e:                                      # OpenSSL.SSL.Error
    #         print("[!]error with {0}\t{1}".format(host, e))
    #         pass                                                # pass: I already write the errors to a LinkedList
    #     except:
    #         print("[!]general exception")
    #     finally:
    #         cert_chain.tls_version = tls_client.get_cipher_name()
    #         cert_chain.cipher_version = tls_client.get_cipher_version()
    #         new_cert_chain = tls_client.get_peer_cert_chain()
    #         cert_chain.end_time = time.time()


    # for chain in Verifier.certificate_chains:
    #     chain.print_chain_details()

#    Verifier.print_time_to_handshake()
