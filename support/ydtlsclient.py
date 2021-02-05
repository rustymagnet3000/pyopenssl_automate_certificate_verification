from support.ydpyopensslcontext import OpenSSLContextHelper
from OpenSSL.SSL import Connection
import time


class YDTLSClient:

    def __init__(self, host, sock, path_to_ca_certs):
        """
        Creates a OpenSSL.SSL.Connection.
        :param host: str of hostname
        :param sock: the live socket
        :param path_to_ca_certs: string path to cert fplder
        """
        self.host = bytes(host, 'utf-8')
        self.sock = sock
        self.tls_client = None
        self.start_time = None
        self.end_time = None
        self.truststore_path = path_to_ca_certs

    def __enter__(self):
        """
        The do_handshake() call can throw.  Especially if it could not verify the Cert Chain.  But this is suppressed
        in the YDSocket class that is closely couple to this class ( as it involves nested With statements )
        :return: self
        """
        self.start_time = time.time()
        self.tls_client = Connection(OpenSSLContextHelper.get_context(self.truststore_path), self.sock)
        self.tls_client.set_tlsext_host_name(self.host)             # Ensures ServerName for Verify() callbacks
        self.tls_client.set_connect_state()                         # set to work in client mode
        self.tls_client.do_handshake()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Sets end time of TLS Handshake
        """
        self.end_time = time.time()
