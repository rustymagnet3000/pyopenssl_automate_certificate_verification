# PyOpenSSL playground

### Setup
`pip3 install -r requirements.txt`
### Usage
`python3 main.py`
### Background
This repo uses `pyOpenSSL`.  

For a real-time lookup, the `main.py` script connects to a server and verifies the certificate chain.This relies on `OpenSSL.SSL` from `pyOpenSSL`.  

For offline checks - when you have all the trusted and untrusted certificates locally - the `class CertificateChecker` performs the checks with `OpenSSL.crypto` from `pyOpenSSL`.



```
******************************	Unit Tests for OpenSSL.SSL	******************************
[*]OpenSSL: b'OpenSSL 1.1.1h  22 Sep 2020'
[*]c_rehash:	b'Doing /path/python_openssl_playground/support/ca_files\n'
[*]Found 2 certificate hash values in path:/path/to/ca-files
[*]connected: stackoverflow.com	('151.101.129.69', 443)
[*]connected: httpbin.org	('52.2.65.80', 443)
[*]connected: github.com	('140.82.121.4', 443)
[*]connected: google.com	('216.58.212.238', 443)

********** stackoverflow.com **********
[*] pass	|	1	|		Let's Encrypt Authority X3
[*] pass	|	0	|		*.stackexchange.com

********** httpbin.org **********
[*] pass	|	1	|		Amazon
[*] pass	|	0	|		httpbin.org

********** github.com **********
[*] fail:20	|	1	|		DigiCert SHA2 High Assurance Server CA

********** google.com **********
[*] fail:20	|	1	|		GTS CA 1O1
```

`pyOpenSSL` is a thin wrapper on top of the `C` based `OpenSSL`.  `pyOpenSSL` is a good way to get familiar with the `C OpenSSL APIs`, `Structs` and `Flags`.  

### Design choices
The `main.py` file relies on `OpenSSL.SSL` from `pyOpenSSL`.  The notable components:
  - Opens a `Socket` to a server.
  - `context = Context(TLSv1_2_METHOD)` create an object instance used for setting up new SSL connections.
  - The `context` sets `load_verify_locations` to a directory of Certificates.
  - The `context` sets `set_verify(VERIFY_PEER, verify_cb)` to require a certificate and then callback with the `verify` result.

The `class CertificateChecker` relies on `OpenSSL.crypto` from `pyOpenSSL`.

### Out of band work
Not all of the code here is done by `PyOpenSSL`. If you type `man verify` from a terminal it will show an `OpenSSL` help page.

> -CApath directory
>     A directory of trusted certificates. The certificates should have names of
>     the form: hash.0 or have symbolic links to them of this form ("hash" is the
>     hashed certificate subject name: see the -hash option of the x509 utility).
>     Under Unix the c_rehash script will automatically create symbolic links to a
>     directory of certificates.

To do this:
```
export CERTS=/Users/{path_to_your_certs}
/path/to/openssl/bin/c_rehash ${CERTS}
```
Don't ignore `c_rehash`.

> rehash scans directories and calculates a hash value of each ".pem", ".crt", ".cer", or ".crl" file in the specified directory list and creates symbolic links for each file

If you don't have the `symbolic links` the `verify step` will fail.

### A good directory of Root and Int Certificate Authorities

![ca-files](/images/2020/11/ca-files.png)

### Not for production
A reminder from https://pypi.org/project/pyOpenSSL/:

> Note: The Python Cryptographic Authority strongly suggests the use of pyca/cryptography where possible. If you are using pyOpenSSL for anything other than making a TLS connection you should move to cryptography and drop your pyOpenSSL dependency.

