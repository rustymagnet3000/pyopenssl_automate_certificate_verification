#!/usr/bin/python3
from socket import socket, gaierror, AF_INET, SOCK_STREAM
from texttable import Texttable


class SocketSetup:
    table = Texttable()
    table.set_cols_width([50, 10, 30])
    table.set_deco(table.BORDER | Texttable.HEADER | Texttable.VLINES)
    open_sockets = []
    bad_sockets = 0

    def __init__(self, host):
        self.host = host
        self.port = 443
        self.sock = socket(AF_INET, SOCK_STREAM)

    def connect_socket(self):
        des = (self.host, self.port)
        try:
            self.sock.connect(des)
            SocketSetup.table.add_row([self.host, 'connected', self.sock.getpeername()])
            SocketSetup.open_sockets.append(self)
        except gaierror as e:
            SocketSetup.table.add_row([self.host, 'fail', 'Socket.gaierror'])
            SocketSetup.bad_sockets += 1
        except:
            SocketSetup.table.add_row([self.host, 'fail', 'Socket error. unhandled'])
            SocketSetup.bad_sockets += 1

    @staticmethod
    def print_all_connections():
        SocketSetup.table.header(['Hostnames', 'result', 'Good {0} / Bad {1} '.format(len(SocketSetup.open_sockets),
                                                                                      SocketSetup.bad_sockets)])
        print("\n" + SocketSetup.table.draw() + "\n")

    @staticmethod
    def clean_up():
        for s in SocketSetup.open_sockets:
            s.sock.close()