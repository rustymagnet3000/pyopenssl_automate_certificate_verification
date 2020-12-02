#!/usr/bin/python3
from socket import socket, gaierror, AF_INET, SOCK_STREAM
from texttable import Texttable


class SocketSetup:
    def __init__(self, host):
        self.port = 443
        self.des = (host, self.port)
        self.sock = socket()
        self.sock.setblocking(False)


    def yd_connect(self)
        self.sock.connect(self.des)  # Try block to capture dead endpoints


    table.add_row([host, 'connected', sock.getpeername()])

    def print_all_connections(self):
        table = Texttable()
        table.set_cols_width([50, 10, 30])
        table.set_deco(table.BORDER | Texttable.HEADER | Texttable.VLINES)
        table.header(['Hostname', 'result', 'server IP'])