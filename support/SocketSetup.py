#!/usr/bin/python3
from socket import socket, gaierror, AF_INET, SOCK_STREAM
from texttable import Texttable


class SocketSetup:
    table = Texttable()
    table.set_cols_width([50, 10, 30])
    table.set_deco(table.BORDER | Texttable.HEADER | Texttable.VLINES)
    table.header(['Hostname', 'result', 'server IP'])
    
    def __init__(self):
        self.port = 443
        self.sock = socket(AF_INET, SOCK_STREAM)

    def connect_socket(self, host):
        result = self.sock.connect_ex((host, self.port))
        if result == 0:
            SocketSetup.table.add_row([host, 'connected', self.sock.getpeername()])
        else:
            SocketSetup.table.add_row([host, 'fail ({})'.format(result), 'Socket error. Unreachable host'])

    @staticmethod
    def print_all_connections():
        print("\n" + SocketSetup.table.draw() + "\n")
