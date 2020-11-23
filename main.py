#!/usr/bin/python3
from pathlib import Path
from os import getcwd
from socket import socket
from OpenSSL.SSL import (
    Connection,
    TLSv1_2_METHOD,
    OP_NO_SSLv2,
    OP_NO_SSLv3,
    OP_NO_TLSv1,
    Context,
    VERIFY_PEER,
    WantReadError
)
from support.CertCheck import CertificateChecker
from support.PyOpenSSLUnitTests import TestCertificateChecker


def verify_cb(conn, cert, err_num, depth, ok):
    """
    Callback from context.set_verify(VERIFY_PEER, verify_cb)
    :return: ok
    """
    if not ok:
        print('[!]Certificate problem:', cert.get_subject().CN, 'chain depth', depth, 'verification failed:', err_num)
    return ok


def verify_cert_cert_from_host(host: str):
    """
        Create Stream socket and connects.  Blocking.  This is a connection oriented socket
        The SSLContext.wrap_socket()method returns an SSLSocket.
        upgrade the socket to TLS without any certificate verification, to obtain the certificate in bytes
    """
    # # # # # # # # # # # Socket # # # # # # # # # # #
    sock = socket()
    sock.setblocking(True)
    sock.connect_ex(sock.getsockname())
    des = (host, 443)
    print('[*]Connect issued...')
    sock.connect(des)
    print('[*]connected: {0}\t{1}'.format(host, sock.getpeername()))

    # # # # # # # # # # # Context # # # # # # # # # # #
    context = Context(TLSv1_2_METHOD)
    context.set_options(OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_TLSv1)
    context.get_cert_store().set_flags(0x80000)
    ca_dir = Path(getcwd() + '/support/ca_files')
    context.load_verify_locations(cafile=None, capath=ca_dir.__bytes__())
    context.set_verify(VERIFY_PEER, verify_cb)

    # # # # # # # # # # # Create TLS client with OpenSSL.SSL.Context and socket # # # # # # # # # # #
    tls_client = Connection(context, sock)
    tls_client.set_connect_state()                          # set to work in client mode

    try:
        tls_client.do_handshake()
        print('[*]Handshake succeeded...')
        CertificateChecker.print_cert_info(tls_client.get_peer_certificate())
    except WantReadError:
        print("[-]WantReadError")
    except:
        print("[!]general exception")
    finally:
        sock.close()
        return None


if __name__ == '__main__':
    print(CertificateChecker.openssl_version())
    print("{0}\tUnit Tests for OpenSSL.SSL\t{0}".format('***' * 10))
    verify_cert_cert_from_host('stackoverflow.com')


