from support.YDOpenSSLContextHelper import OpenSSLContextHelper
from support.YDCertChainLList import SinglyLinkedList
from OpenSSL.SSL import Connection
import time


class YDTLSClient:

    def __init__(self, host, sock, path_to_ca_certs):
        """
        Creates a Node to add to the Cert Chain Linked List
        :param host: str of hotsname
        :param sock: the live socket
        :param path_to_ca_certs: string path to cert fplder
        """
        self.host = bytes(host, 'utf-8')
        self.sock = sock
        self.cert_chain = SinglyLinkedList(self.host)
        self.truststore_path = path_to_ca_certs

    def __enter__(self):
        """
        The do_handshake() call can throw.  Especially if it could not verify the Cert Chain.  But this is suppressed
        in the YDSocket class that is closely couple to this class ( as it involves nested With statements )
        :return: self
        """
        self.cert_chain.start_time = time.time()
        self.tls_client = Connection(OpenSSLContextHelper.get_context(self.truststore_path), self.sock)
        self.tls_client.set_tlsext_host_name(self.host)             # Ensures ServerName for Verify() callbacks
        self.tls_client.set_connect_state()                         # set to work in client mode
        self.tls_client.do_handshake()
        self.cert_chain.tls_version = self.tls_client.get_protocol_version_name()
        self.cert_chain.cipher_name = self.tls_client.get_cipher_name()
        self.cert_chain.end_time = time.time()
        return self.cert_chain

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        """
        return True

