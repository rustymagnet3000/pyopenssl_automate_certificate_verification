#!/usr/bin/python3
from socket import socket, gaierror
import time
from os import getcwd, environ
from OpenSSL.SSL import (
    Connection,
    Error,
    WantReadError
)

import argparse
from support.Verifier import Verifier
from support.HostNameClean import HostNameCleaner
from support.CertCheck import CertificateChecker
from support.CertChainLList import SinglyLinkedList
from texttable import Texttable


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
    port = 443

    verifier = Verifier(ca_dir=args.certs_path, c_rehash_loc=args.rehash_path)
    assert (verifier.cert_hash_count > 0)

    table = Texttable()
    table.set_cols_width([50, 10, 30])
    table.set_deco(table.BORDER | Texttable.HEADER | Texttable.VLINES)
    table.header(['Hostname', 'result', 'server IP'])

    for host in hosts:
        des = (host, port)
        sock = socket()
        sock.setblocking(True)
        sock.connect_ex(sock.getsockname())
        tls_client = Connection(verifier.context, sock)
        tls_client.set_tlsext_host_name(bytes(host, 'utf-8'))   # Ensures ServerName when Verify callback invokes
        tls_client.set_connect_state()                          # set to work in client mode
        # create an empty linked list, that sets the Name and Start time
        cert_chain = SinglyLinkedList(host)
        # Add Linked List to global List
        Verifier.certificate_chains.append(cert_chain)
        cert_chain.start_time = time.time()
        try:
            sock.connect(des)  # Try block to capture dead endpoints
            table.add_row([host, 'connected', sock.getpeername()])
            tls_client.do_handshake()

            cert_chain.tls_version = tls_client.get_cipher_name()
            cert_chain.cipher_version = tls_client.get_cipher_version()
            new_cert_chain = tls_client.get_peer_cert_chain()
            cert_chain.end_time = time.time()
        except gaierror as e:
            table.add_row([host, 'fail', 'Socket error'])
        except WantReadError:
            print("[!]WantReadError")
        except Error as e:                                      # OpenSSL.SSL.Error
            print("[!]error with {0}\t({1}".format(host, e))
            pass                                                # pass: I already write the errors to a LinkedList
        except:
            print("[!]general exception")
        finally:
            print("\n" + table.draw() + "\n")
            sock.close()

    for chain in Verifier.certificate_chains:
        chain.print_chain_details()

#    Verifier.print_time_to_handshake()
