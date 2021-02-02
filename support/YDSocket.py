from socket import (
    socket, getaddrinfo, AF_INET, SOCK_STREAM, IPPROTO_TCP
)
from texttable import Texttable
from support.YDTLSClient import YDTLSClient


class YDSocket:
    table = Texttable()
    table.set_cols_width([50, 10, 30])
    table.set_deco(table.BORDER | Texttable.HEADER | Texttable.VLINES)
    open_sockets = 0
    bad_sockets = 0
    port = 443

    def __init__(self, host):
        self.host = host
        self.sock = socket(AF_INET, SOCK_STREAM)

    def __enter__(self):
        self.sock.setblocking(True)
        getaddrinfo(self.host, YDSocket.port, proto=IPPROTO_TCP)
        self.sock.connect((self.host, YDSocket.port))
        self.tls_client = YDTLSClient(self.host, self.sock)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.sock.close()

    @staticmethod
    def print_all_connections():
        YDSocket.table.header(['Hostnames', 'result', 'Good {0} / Bad {1} '.format(YDSocket.open_sockets,
                                                                                   YDSocket.bad_sockets)])
        print("\n" + YDSocket.table.draw() + "\n")
