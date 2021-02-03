#!/usr/bin/python3

import OpenSSL
import sys
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from support.YDCertFilesChecker import YDCertFilesChecker
from support.YDSocket import YDSocket
from support.YDTLSClient import YDTLSClient
from support.YDArgParse import parser
from support.YDVerifier import Verifier
from support.YDHostNameClean import HostNameCleaner
import os


if __name__ == "__main__":
    args = parser.parse_args()
    with Verifier(ca_dir=args.certs_path, c_rehash_loc=args.rehash_path) as verifier:
        if args.print_truststore_info:
            for filename in os.listdir(verifier.path_to_ca_certs):
                if filename.endswith('crt') or filename.endswith('.pem') or filename.endswith('.der'):
                    try:
                        with open(os.path.join(verifier.path_to_ca_certs, filename), "r") as f:
                            cert_buffer = f.read()
                            orig_cert = load_certificate(FILETYPE_PEM, bytes(cert_buffer, 'utf-8'))
                            checker = YDCertFilesChecker(orig_cert, filename)
                            checker.add_cert_to_summary_table()
                    except OpenSSL.crypto.Error:
                        print("Error happened in Load Certificate call:", filename)
            YDCertFilesChecker.print_cert_files_summary()

        if args.hostnames_file:
            with HostNameCleaner(args.hostnames_file) as hosts:
                for host in hosts:
                    try:
                        with YDSocket(host) as s:
                            YDSocket.table.add_row([host, 'connected', s.sock.getpeername()])
                            YDSocket.open_sockets += 1
                            with YDTLSClient(host, s.sock, verifier.path_to_ca_certs) as client:
                                cert_chain = client.tls_client.get_peer_cert_chain()
                    except:
                        e = sys.exc_info()[0]
                        YDSocket.handle_socket_errors(host, e)

            YDSocket.print_all_connections()
            Verifier.print_all()
