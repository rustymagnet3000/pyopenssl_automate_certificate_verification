# PyOpenSSL playground

### Setup
`pip3 install -r requirements.txt`
### Usage
`python3 main.py --infile hostnames.txt`
### Background
This repo uses `pyOpenSSL`.  

For a real-time lookup, the `main.py` script connects to a server and verifies the certificate chain.This relies on `OpenSSL.SSL` from `pyOpenSSL`.  

For offline checks - when you have all the trusted and untrusted certificates locally - the `class CertificateChecker` performs the checks with `OpenSSL.crypto` from `pyOpenSSL`.



```
******************************	Unit Tests for OpenSSL.SSL	******************************
[*]OpenSSL 1.1.1h  22 Sep 2020
[*]Creating symbolic links for OpenSSL:
			Doing /path/to/python_openssl_playground/support/ca_files

+------------------------------------------------------------------------------+
|            Hostname                result               server IP            |
+==============================================================================+
| stackoverflow.com                pass         ('151.101.129.69', 443)        |
| httpbin.org                      pass         ('52.2.65.80', 443)            |
| github.com                       pass         ('140.82.121.3', 443)          |
| google.com                       pass         ('216.58.213.110', 443)        |
| blackhole-sun.deadlink           fail         Socket error                   |
+------------------------------------------------------------------------------+


+--------------------------------------------------------------------+
|            stackoverflow.com                 Result       Depth    |
+====================================================================+
| Let's Encrypt Authority X3                 pass         1          |
| *.stackexchange.com                        pass         0          |
+--------------------------------------------------------------------+


+--------------------------------------------------------------------+
|               httpbin.org                    Result       Depth    |
+====================================================================+
| Amazon                                     pass         1          |
| httpbin.org                                pass         0          |
+--------------------------------------------------------------------+


+--------------------------------------------------------------------+
|                github.com                    Result       Depth    |
+====================================================================+
| DigiCert SHA2 High Assurance Server CA     fail:20      1          |
+--------------------------------------------------------------------+


+--------------------------------------------------------------------+
|                google.com                    Result       Depth    |
+====================================================================+
| GTS CA 1O1                                 fail:20      1          |
+--------------------------------------------------------------------+


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
In the below example, you have two certificates and two symbolic links created by `c_rehash`.
```
4f06f81d.0
2401d14f.0
httpbin_int_ca.pem
stackoverflow_int_ca.pem
```
Wait!  Don't you need the full `certificate chain`?  That depends on what `flags` you passed into the `Context` for `OpenSSL`. You can find the `Partial-Chain` flag added in this repo.  Just the `Int CA` is enough to verify a peer. No `Root CA` required.

### Not for production
A reminder from https://pypi.org/project/pyOpenSSL/:

> Note: The Python Cryptographic Authority strongly suggests the use of pyca/cryptography where possible. If you are using pyOpenSSL for anything other than making a TLS connection you should move to cryptography and drop your pyOpenSSL dependency.

