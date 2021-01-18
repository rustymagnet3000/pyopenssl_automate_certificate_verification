#!/usr/bin/python3
from OpenSSL.crypto import X509, load_certificate, FILETYPE_PEM
from OpenSSL.SSL import SSLEAY_VERSION, SSLeay_version
import datetime
from termcolor import colored
import os


class YDCertFilesChecker:
    summary = {
        "root_certs": 0,
        "int_certs": 0,
        "leaf_certs": 0,
        "expired_certs": 0,
        "openssl_version": str(SSLeay_version(SSLEAY_VERSION), 'utf-8')
    }

    def __init__(self, cert: X509):
        if isinstance(cert, X509):
            self.cert = cert

    def __enter__(self):
        if self.cert.has_expired():
            YDCertFilesChecker.summary['expired_certs'] += 1
        if self.cert.get_issuer().CN == self.cert.get_subject().CN:
            YDCertFilesChecker.summary['root_certs'] += 1
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return None

    def print_cert_info(self):
        s = 'commonName: {commonname}, issuer: {issuer} notAfter:  {notafter},\nExpired: {expired}'.format(
            commonname=self.cert.get_subject().CN,
            issuer=self.cert.get_issuer().CN,
            notafter=YDCertFilesChecker.pretty_date(self.cert.get_notAfter()),
            expired=self.cert.has_expired()
        )
        print(s)

    @staticmethod
    def pretty_date(date_from_cert: bytes):
        date = (datetime.datetime.strptime(date_from_cert.decode('ascii'), '%Y%m%d%H%M%SZ'))
        return f"{date:%d-%b-%Y}"
