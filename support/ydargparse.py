import argparse
from os import getcwd, environ

parser = argparse.ArgumentParser(description="PyOpenSSL")

parser.add_argument(
    '--hostnames-file',
    '-f',
    help='Path to text file that includes hostnames to check',
    type=argparse.FileType('r', encoding='UTF-8'),
    required=False)

parser.add_argument(
    "-c",
    "--certs-path",
    help='Path to directory of Root and Intermediate Cert Authority certificates',
    default=getcwd() + '/support/ca_files',
    required=False)

parser.add_argument(
    "-r",
    "--rehash-path",
    help='Path to OpenSSL\'s c_rehash tool. This generates the symbolic required for OpenSSL\'s Verify() to work'
         ' if you don\'t include this value, it will default to ~/openssl/bin',
    default=environ['HOME'] + '/usr/bin/c_rehash',
    required=False)

parser.add_argument(
    "-p",
    "--print-truststore-info",
    help='Prints out information about the directory of Root and Intermediate Cert Authority certificates. '
         'This is the Truststore.',
    required=False,
    action="store_true")

parser.add_argument(
    "-n",
    "--native-ssl",
    help='Instead of pyOpenSSL this uses the native \'ssl\' module.  '
         'Useful when the endpoint might timeout during do_handshake()',
    required=False,
    action="store_true")
