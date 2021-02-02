from support.YDOpenSSLContextHelper import OpenSSLContextHelper
from support.YDVerifier import Verifier
from support.YDCertChainLList import SinglyLinkedList
from OpenSSL.SSL import Connection
import time


class YDTLSClient:
    def __init__(self, host, sock, path_to_ca_certs):
        self.host = bytes(host, 'utf-8')
        self.sock = sock
        self.cert_chain = SinglyLinkedList(self.host)
        self.truststore_path = path_to_ca_certs

    def __enter__(self):
        self.cert_chain.start_time = time.time()
        self.tls_client = Connection(OpenSSLContextHelper.get_context(self.truststore_path), self.sock)
        self.tls_client.set_tlsext_host_name(self.host)             # Ensures ServerName when Verify() callbacks
        self.tls_client.set_connect_state()                         # set to work in client mode
        Verifier.certificate_chains.append(self.cert_chain)
        self.tls_client.do_handshake()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cert_chain.tls_version = self.tls_client.get_cipher_name()
        self.cert_chain.cipher_version = self.tls_client.get_cipher_version()
        self.cert_chain.end_time = time.time()
