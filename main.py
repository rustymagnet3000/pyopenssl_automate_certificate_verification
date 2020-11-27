#!/usr/bin/python3
from support.Verifier import Verifier
from support.CertCheck import CertificateChecker
from support.CertChainLList import CertNode, SinglyLinkedList
from support.PyOpenSSLUnitTests import TestCertificateChecker, TestOpenSSLVerifySpeed
from texttable import Texttable
import unittest




if __name__ == '__main__':

    suite = unittest.TestLoader().loadTestsFromTestCase(TestOpenSSLVerifySpeed)
    unittest.TextTestRunner(verbosity=0).run(suite)

    # hosts = ['stackoverflow.com', 'httpbin.org', 'github.com', 'google.com', 'blackhole-sun.deadlink']
    # port = 443
    # verifier = Verifier()
    # if verifier.cert_hash_count == 0:
    #     exit(99)
    # table = Texttable()
    # table.set_cols_width([30, 10, 30])
    # table.set_deco(table.BORDER | Texttable.HEADER | Texttable.VLINES )
    # table.header(['Hostname', 'result', 'server IP'])
    #
    # for host in hosts:
    #     des = (host, port)
    #     sock = socket()
    #     sock.setblocking(True)
    #     sock.connect_ex(sock.getsockname())
    #     tls_client = Connection(verifier.context, sock)
    #     tls_client.set_tlsext_host_name(bytes(host, 'utf-8'))   # Ensures ServerName when Verify callback invokes
    #     tls_client.set_connect_state()                          # set to work in client mode
    #
    #     try:
    #         sock.connect(des)                                   # Try block to capture dead endpoints
    #         table.add_row([host, 'pass', sock.getpeername()])
    #         tls_client.do_handshake()
    #     except gaierror as e:
    #         table.add_row([host, 'fail', 'Socket error'])
    #     except WantReadError:
    #         print("[!]WantReadError")
    #     except Error as e:                                      # OpenSSL.SSL.Error
    #         pass                                                # pass: I already write the errors to a LinkedList
    #     except:
    #         print("[!]general exception")
    #     finally:
    #         sock.close()
    #
    # print("\n" + table.draw() + "\n")
    # for chain in Verifier.certificate_chains:
    #     chain.print_entire_chain()
