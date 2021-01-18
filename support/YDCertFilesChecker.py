#!/usr/bin/python3
from OpenSSL.version import __version__
from OpenSSL.crypto import (
    X509,
    load_certificate,
    FILETYPE_PEM
)
from OpenSSL.SSL import (
    SSLEAY_VERSION,
    SSLeay_version
)
import datetime
import os


class YDCertFilesChecker:
    def __init__(self, dir_of_certificates):
        self.dir_of_certs = dir_of_certificates
        self.summary = {
            "openssl_version": str(SSLeay_version(SSLEAY_VERSION), 'utf-8'),
            "root_certs": 0,
            "int_certs": 0,
            "leaf_certs": 0,
            "expired_certs": 0
        }

    def __enter__(self):
        for file in os.listdir(self.dir_of_certs):
            with open(os.path.join(self.dir_of_certs, file), "r") as f:
                cert_buf = f.read()
                cert = load_certificate(FILETYPE_PEM, cert_buf)
                if isinstance(cert, X509):
                    self.expired_cert_check(cert)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print('[*] '.format(self.summary))

    def expired_cert_check(self, cert: X509):
        if cert.has_expired():
            self.summary['expired_certs'] += 1



    @staticmethod
    def print_cert_info(cert: X509):
        s = '''
        commonName: {commonname}
        issuer: {issuer}
        notBefore: {notbefore}
        notAfter:  {notafter}
        serial num: {serial_number}
        Expired: {expired}
        '''.format(
            commonname=cert.get_subject().CN,
            issuer=cert.get_issuer().CN,
            notbefore=LeafVerify.pretty_date(cert.get_notBefore()),
            notafter=LeafVerify.pretty_date(cert.get_notAfter()),
            serial_number=cert.get_serial_number(),
            expired=cert.has_expired()
        )
        print(s)

    @staticmethod
    def pretty_date(date_from_cert: bytes):
        date = (datetime.datetime.strptime(date_from_cert.decode('ascii'), '%Y%m%d%H%M%SZ'))
        return(f"{date:%d-%b-%Y}")