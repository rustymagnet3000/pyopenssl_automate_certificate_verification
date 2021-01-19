#!/usr/bin/python3
from OpenSSL.crypto import X509, load_certificate, FILETYPE_PEM, X509Extension
from OpenSSL.SSL import SSLEAY_VERSION, SSLeay_version
from datetime import timedelta, date, datetime
from termcolor import colored
import os
from operator import eq


class YDCertFilesChecker:
    summary = {
        "root_certs": 0,
        "int_certs": 0,
        "leaf_certs": 0,
        "unknown_certs": 0,
        "expired_certs": 0,
        "expired_60_days": 0,
        "openssl_version": str(SSLeay_version(SSLEAY_VERSION), 'utf-8')
    }

    def __init__(self, cert: X509):
        assert isinstance(cert, X509)
        self.cert = cert

    def __enter__(self):
        self.classify_cert_dates()
        self.classify_cert()
        return self

    def classify_cert(self):
        """
        Classifies certificate against Root, Int CA or Leaf.
        A lot of the values are optional, so check has to work against Certs without Extensions.
        cert_ext == dictionary of X509Extension short name and data.
        Parameters: cert (crypto.X509)
        Returns: None
        """
        cert_ext = {ext.get_short_name(): ext.get_data() for ext in
                    [self.cert.get_extension(i) for i in range(self.cert.get_extension_count())]}
        possible_int_ca = X509Extension(b'basicConstraints', True, b'CA:TRUE')
        definite_int_ca = X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:1")

        if self.cert.get_issuer().CN == self.cert.get_subject().CN:
            YDCertFilesChecker.summary['root_certs'] += 1
        elif b'basicConstraints' in cert_ext and eq(cert_ext[b'basicConstraints'], possible_int_ca.get_data()):
            YDCertFilesChecker.summary['int_certs'] += 1
        elif b'basicConstraints' in cert_ext and eq(cert_ext[b'basicConstraints'], definite_int_ca.get_data()):
            YDCertFilesChecker.summary['int_certs'] += 1
        elif b'subjectAltName' in cert_ext:
            YDCertFilesChecker.summary['leaf_certs'] += 1
        else:
            YDCertFilesChecker.summary['unknown_certs'] += 1

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

    def classify_cert_dates(self):
        if self.cert.has_expired():
            YDCertFilesChecker.summary['expired_certs'] += 1

        cert_date = (datetime.datetime.strptime(self.cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'))
        delta = timedelta(days=60)
        soon_exp_date = datetime.datetime.now() + delta
        if cert_date < soon_exp_date:
            print(f"Cert expires in 60 days")

    @staticmethod
    def pretty_date(date_from_cert: bytes):
        date = (datetime.datetime.strptime(date_from_cert.decode('ascii'), '%Y%m%d%H%M%SZ'))
        return f"{date:%d-%b-%Y}"
