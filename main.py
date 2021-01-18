#!/usr/bin/python3
from OpenSSL.SSL import Error, WantReadError
from OpenSSL.crypto import X509, load_certificate, FILETYPE_PEM
from socket import gaierror, timeout
from support.YDCertFilesChecker import YDCertFilesChecker
from support.YDSocket import YDSocket
from support.YDTLSClient import YDTLSClient
from support.argparsing import parser
from support.Verifier import Verifier
from support.HostNameClean import HostNameCleaner
from support.CertCheck import LeafVerify
import os
import asn1

def summary_print():
    if args.socket_info:
        YDSocket.print_all_connections()
    elif args.time:
        Verifier.print_time_to_handshake()
    elif args.all:
        YDSocket.print_all_connections()
        Verifier.print_time_to_handshake()
        for chain in Verifier.certificate_chains:
            chain.print_chain_details()
    else:
        YDSocket.print_all_connections()


if __name__ == "__main__":
    args = parser.parse_args()
    verifier = Verifier(ca_dir=args.certs_path, c_rehash_loc=args.rehash_path)
    assert (verifier.cert_hash_count > 0)
    decoder = asn1.Decoder()
    for file in os.listdir(verifier.path_to_ca_certs):
        if file.endswith('crt') or file.endswith('.pem') or file.endswith('.der'):
            with open(os.path.join(verifier.path_to_ca_certs, file), "r") as f:
                cert_buf = f.read()
                cert = load_certificate(FILETYPE_PEM, cert_buf)
                with YDCertFilesChecker(cert) as c:
                    #c.print_cert_info()
                    for index in range(c.cert.get_extension_count()):
                        ext = cert.get_extension(index)
                        print(ext.get_short_name())
                        decoder.start(ext.get_data())
                        tag, value = decoder.read()
                        print(tag, type(value))
    print(YDCertFilesChecker.summary)





#
# with args.hostnames_file as file:
#     sanitized_hosts = HostNameCleaner(file)
# hosts = sanitized_hosts.hostnames
#
# verifier = Verifier(ca_dir=args.certs_path, c_rehash_loc=args.rehash_path)
# assert (verifier.cert_hash_count > 0)
#
# for host in hosts:
#     try:
#         with YDSocket(host) as s:
#             YDSocket.table.add_row([host, 'connected', s.sock.getpeername()])
#             YDSocket.open_sockets += 1
#             client = YDTLSClient(host, s.sock, verifier)
#     except timeout:
#         YDSocket.table.add_row([host, 'fail', 'timeout'])
#         YDSocket.bad_sockets += 1
#     except gaierror as e:
#         YDSocket.table.add_row([host, 'fail', 'getaddrinfo error'])
#         YDSocket.bad_sockets += 1
#     except WantReadError:
#         print("[!]WantReadError. Generated by non-blocking Socket")
#     except Error as e:  # OpenSSL.SSL.Error
#         print("[!]error with {0}\t{1}".format(s.host, e))
#     except:
#         YDSocket.table.add_row([host, 'fail', 'Socket error. unhandled'])
#         YDSocket.bad_sockets += 1