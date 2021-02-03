# PyOpenSSL playground

The repo solely relies on `OpenSSL.SSL` from `pyOpenSSL`.  `pyOpenSSL` is a thin wrapper on top of the `C OpenSSL library`.  

If you want to automate the following `OpenSSL commands` for lots of `hostnames` or `certificates`, this repo could help:
```
openssl s_client -partial_chain -CApath /path/to/certs -connect httpbin.org:443

openssl verify -partial_chain -CApath /path/to/certs httpbin-org-leaf.pem
```
### Setup
`pip3 install -r requirements.txt`
### Output
##### Print information about Trust Store OpenSSL will use
```
python3 main.py -p

[*]PyOpenSSL:20.0.0
[*]Creating symbolic links for OpenSSL
[*]Certificates in Trust Store :4

+----------------------------------------------------+----------------------------------------------------+----------------------+------------------------------------------+----------------------+
|                    Subject Name                    |                       Issuer                       |         Type         |                 Filename                 |        Expiry        |
+====================================================+====================================================+======================+==========================================+======================+
| Let's Encrypt Authority X3                         | DST Root CA X3                                     | Unknown              | so_int_ca.pem                            | 17-Mar-2021          |
+----------------------------------------------------+----------------------------------------------------+----------------------+------------------------------------------+----------------------+
| Amazon                                             | Amazon Root CA 1                                   | Unknown              | httpbin-org-IntCA.pem                    | 21-Oct-2040          |
+----------------------------------------------------+----------------------------------------------------+----------------------+------------------------------------------+----------------------+
| DigiCert SHA2 High Assurance Server CA             | DigiCert High Assurance EV Root CA                 | Unknown              | github_int_ca.pem                        | 22-Oct-2028          |
+----------------------------------------------------+----------------------------------------------------+----------------------+------------------------------------------+----------------------+
| GTS CA 1O1                                         | GlobalSign                                         | Unknown              | google_int_ca.pem                        | 15-Dec-2021          |
+----------------------------------------------------+----------------------------------------------------+----------------------+------------------------------------------+----------------------+

+------------------------------------------------------------------------+----------------------+
|                         Expired/Expiring Cert                          |     Expiry Date      |
+========================================================================+======================+
| Let's Encrypt Authority X3                                             | 17-Mar-2021          |
+------------------------------------------------------------------------+----------------------+

[*]clean-up.  Deleted all symbolic links.
```
### Output
##### Verify hostnames and certificate chains
```
python3 main.py -f hostnames.txt            # use default Certificate folder ( /support/ca_files )

[*]OpenSSL 1.1.1h  22 Sep 2020
[*]Creating symbolic links for OpenSSL
[*]Certificates in Trust Store :4

+----------------------------------------------------+------------+--------------------------------+
|                      Hostname                      |   result   |           server IP            |
+====================================================+============+================================+
| stackoverflow.com                                  | connected  | ('151.101.193.69', 443)        |
| httpbin.org                                        | connected  | ('184.72.216.47', 443)         |
| github.com                                         | connected  | ('140.82.121.4', 443)          |
| google.com                                         | connected  | ('172.217.169.46', 443)        |
| microsoft.com                                      | connected  | ('13.77.161.179', 443)         |
+----------------------------------------------------+------------+--------------------------------+


+----------------------------------------------------+------------+------------+------------------------------------------+
|                      Hostname                      |    Time    |   Cipher   |               TLS Protocol               |
+====================================================+============+============+==========================================+
| stackoverflow.com                                  | 0.114      | TLSv1.2    | ECDHE-RSA-AES128-GCM-SHA256              |
| httpbin.org                                        | 0.354      | TLSv1.2    | ECDHE-RSA-AES128-GCM-SHA256              |
| github.com                                         | 0.156      | TLSv1.2    | ECDHE-RSA-AES128-GCM-SHA256              |
| google.com                                         | 0.098      | TLSv1.2    | ECDHE-ECDSA-CHACHA20-POLY1305            |
| microsoft.com                                      | failed     | None       | None                                     |
|                                                    | verify     |            |                                          |
+----------------------------------------------------+------------+------------+------------------------------------------+

```

### Usage
```
usage: main.py [-h] [--hostnames-file HOSTNAMES_FILE] -c CERTS_PATH [-r REHASH_PATH] [-p PRINT_TRUSTSTORE_INFO] [-s]
               [-t] [-all]
               
PyOpenSSL

optional arguments:
  -h, --help            show this help message and exit
  --hostnames-file HOSTNAMES_FILE, -f HOSTNAMES_FILE
                        Path to text file that includes hostnames to check
  -c CERTS_PATH, --certs-path CERTS_PATH
                        Path to directory of Root and Intermediate Cert Authority certificates
  -r REHASH_PATH, --rehash-path REHASH_PATH
                        Path to OpenSSL's c_rehash tool. This generates the symbolic required for OpenSSL's Verify()
                        to workIf you don't include this value, it will default to ~/openssl/bin
  -p PRINT_TRUSTSTORE_INFO, --print-truststore-info PRINT_TRUSTSTORE_INFO
                        Prints out information about the directory of Root and Intermediate Cert Authority
                        certificates. This is the Truststore.
  -s, --socket-info     Prints the I.P. address returned from from getaddrinfo()
  -t, --time            Prints the time for tls_client.do_handshake() to complete
  -all, --all           Prints all information available
```


### Design choices

`pyOpenSSL` is a good way to get familiar with the `C OpenSSL APIs`, `Structs` and `Flags`.  This repo does NOT use `Python's` more commonly used libraries `ssl` or `cryptography`.

###### The notable decisions:
  - Opens a `Socket` to a server.
  - The code will report errors if a hostname fails `socket.getaddr` or `socket.connect()`.
  - `context = Context(TLSv1_2_METHOD)` create an object instance used for setting up new SSL connections.
  - `TLSv1_2_METHOD` is chosen because `TLSv1_3_METHOD` is not available in `pyOpenSSL`.
  - The `context` sets `load_verify_locations` to a directory of Certificates.
  - The `context` sets `set_verify(VERIFY_PEER, verify_cb)` to require a certificate and then callback with the `verify` result.
 - `Python Context Managers` are used to kick-off the `c_rehash` tool and clean-up the `symbolic links` it generated.

The `class LeafVerify` relies on `OpenSSL.crypto` from `pyOpenSSL`.

### Underneath the code
Don't ignore the `openSSL` tool called: `c_rehash`.  If you type `man verify` from a terminal it will show an `OpenSSL` help page:

> -CApath directory
>     A directory of trusted certificates. The certificates should have names of
>     the form: hash.0 or have symbolic links to them of this form ("hash" is the
>     hashed certificate subject name: see the -hash option of the x509 utility).
>     Under Unix the c_rehash script will automatically create symbolic links to a
>     directory of certificates.

The `c_rehash` tool does that work for you:
> rehash scans directories and calculates a hash value of each ".pem", ".crt", ".cer", or ".crl" file in the specified directory list and creates symbolic links for each file


The code in this repo assumes you have a directory of Certificates.  These certificates represent your `Trust Store` - and you have the `c_rehash`tool installed:
```
class Verifier:
    def __init__(self, ca_dir=Path(getcwd() + '/support/ca_files'),
                 c_rehash_loc=environ['HOME'] + '/openssl/bin/c_rehash'):
```              


If you don't have the `symbolic links` the `verify step` will fail.

### A good directory of Root and Int Certificate Authorities
After `c_rehash` runs on two certificates, it will auto generate two symbolic links:
```
4f06f81d.0
2401d14f.0
httpbin_int_ca.pem
stackoverflow_int_ca.pem
```
Wait!  Don't you need the full `certificate chain`?  That depends on what `flags` you passed into the `Context` for `OpenSSL`. You can find the `Partial-Chain` flag added in this repo.  Just the `Int CA` is enough to verify a peer. No `Root CA` required.

### Testing old versions of OpenSSL
Is it possible to downgrade the `OpenSSL library` used by `pyOpenSSL`?  Firstly, it is useful to check:

```
from OpenSSL.debug import _env_info

if __name__ == '__main__':
    print(_env_info)
```
That reveals:
```
pyOpenSSL: 20.0.0
cryptography: 3.2.1
cffi: 1.14.3
cryptography's compiled against OpenSSL: OpenSSL 1.1.1h  22 Sep 2020
cryptography's linked OpenSSL: OpenSSL 1.1.1h  22 Sep 2020
Python's OpenSSL: OpenSSL 1.1.1g  21 Apr 2020
Python executable: /Users/a9006113/ydvenv/bin/python
Python version: 3.8.5 (default, Sep 18 2020, 11:34:27) 
[Clang 11.0.3 (clang-1103.0.32.62)]
Platform: darwin
```
To lower the `OpenSSL version`, lower the `Cryptography` version.  With a `Python Virtual Environment` it is simple and safe to have a throwaway setup, when testing multiple versions.