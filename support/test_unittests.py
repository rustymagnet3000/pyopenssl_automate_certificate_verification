from ydleafverify import YDLeafVerify
from testcerts import (
    good_leaf_cert_pem,
    bad_leaf_cert_pem
)
from OpenSSL.crypto import (
    X509Store,
    X509
)


def test_good_leaf_cert():
    check = YDLeafVerify(good_leaf_cert_pem)
    assert(check.verify_cert())


def test_openssl_types():
    check = YDLeafVerify(bad_leaf_cert_pem)
    assert(isinstance(check.trusted_certs, X509Store))
    assert(isinstance(check.untrusted_leaf, X509))
