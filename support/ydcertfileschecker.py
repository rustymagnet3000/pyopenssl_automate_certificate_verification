from OpenSSL.crypto import X509, X509Extension
from datetime import datetime, timedelta
from time import strptime, strftime, mktime
from texttable import Texttable
from operator import eq
from enum import Enum


class CertType(Enum):
    ROOT_CA = "root CA"
    INT_CA = "intermediate CA"
    LEAF = "Leaf cert"
    UNKNOWN = "Unknown"


class YDCertFilesChecker:
    expired_certs = []
    expiring_certs = []
    each_cert_summary_info = []
    summary = {
        "root_certs": 0,
        "int_certs": 0,
        "leaf_certs": 0,
        "unknown_certs": 0
    }

    def __init__(self, cert: X509, filename: str):
        self.filename = filename
        assert isinstance(cert, X509)
        self.cert = cert

    def add_cert_to_summary_table(self):
        """
        Adds details of the Cert to a TextTable
        :return: None
        """
        YDCertFilesChecker.each_cert_summary_info.append([
            self.cert.get_subject().CN,
            self.cert.get_issuer().CN,
            self._classify_cert().value,
            self.filename,
            YDCertFilesChecker.pretty_date(self.cert)]
        )
        self._check_if_cert_expired()
        return None

    def _classify_cert(self):
        """
        Classifies certificate against Root, Int CA or Leaf.
        A lot of the values are optional, so check has to account for missing keys / None.
        cert_ext == dictionary of X509Extension short name and data.
        Parameters: cert (crypto.X509)
        Returns: CertType
        """
        cert_ext = {ext.get_short_name(): ext.get_data() for ext in
                    [self.cert.get_extension(i) for i in range(self.cert.get_extension_count())]}
        possible_int_ca = X509Extension(b'basicConstraints', True, b'CA:TRUE')
        definite_int_ca = X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:1")

        if self.cert.get_issuer().CN == self.cert.get_subject().CN:
            YDCertFilesChecker.summary['root_certs'] += 1
            return CertType.ROOT_CA
        elif b'basicConstraints' in cert_ext and eq(cert_ext[b'basicConstraints'], possible_int_ca.get_data()):
            YDCertFilesChecker.summary['int_certs'] += 1
            return CertType.INT_CA
        elif b'basicConstraints' in cert_ext and eq(cert_ext[b'basicConstraints'], definite_int_ca.get_data()):
            YDCertFilesChecker.summary['int_certs'] += 1
            return CertType.INT_CA
        elif b'subjectAltName' in cert_ext:
            YDCertFilesChecker.summary['leaf_certs'] += 1
            return CertType.LEAF
        else:
            YDCertFilesChecker.summary['unknown_certs'] += 1
            return CertType.UNKNOWN

    def _check_if_cert_expired(self):
        """
        Takes the current Cert: x509 and:
        Expired cert -> Uses the .has_expired() attribute.
        Expiring cert -> gets the notAfter() date in Epoch Time. Compared with Time Delta of 60 days.
        :return: None
        """
        temp_time = strptime(self.cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        epoch_cert_datetime = datetime.fromtimestamp(mktime(temp_time)).timestamp()
        delta = timedelta(seconds=3600 * 24 * 60)
        soon_exp_date = (datetime.now() + delta).timestamp()

        if self.cert.has_expired():
            YDCertFilesChecker.expired_certs.append(self.cert)
        elif soon_exp_date > epoch_cert_datetime:
            YDCertFilesChecker.expiring_certs.append(self.cert)

    @staticmethod
    def print_cert_files_summary():
        """
        First, prints all the Certs in a TextTable.  Then print the Expired/Expiring cert information.
        :return: None
        """
        table = Texttable(max_width=200)
        table.set_cols_width([50, 50, 20, 40, 20])
        table.header(['Trust Store certificate', 'Issuer', 'Type', 'Filename', 'Expiry'])
        table.set_deco(table.BORDER | Texttable.HEADER | Texttable.VLINES | Texttable.HLINES)

        for i in YDCertFilesChecker.each_cert_summary_info:
            table.add_row(i)

        print("\n" + table.draw() + "\n")

        if len(YDCertFilesChecker.expired_certs) > 0 or len(YDCertFilesChecker.expiring_certs) > 0:
            table = Texttable(max_width=100)
            table.set_cols_width([70, 20])
            table.set_deco(table.BORDER | Texttable.HEADER | Texttable.VLINES)

            table.header(['Expired/Expiring Cert', 'Expiry Date'])
            for cert in YDCertFilesChecker.expired_certs:
                table.add_row([cert.get_subject().CN, YDCertFilesChecker.pretty_date(cert)])

            for cert in YDCertFilesChecker.expiring_certs:
                table.add_row([cert.get_subject().CN, YDCertFilesChecker.pretty_date(cert)])

            print("\n" + table.draw() + "\n")
        else:
            print("[*]No Expired of Expiring certs")
        return None

    @staticmethod
    def pretty_date(cert):
        temp_time = strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        date_str = strftime('%d-%b-%Y', temp_time)
        return f"{date_str}"
