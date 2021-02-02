from OpenSSL.SSL import (
    TLSv1_2_METHOD,
    OP_NO_SSLv2,
    OP_NO_SSLv3,
    OP_NO_TLSv1,
    Context,
    VERIFY_PEER
)

from support.YDVerifier import Verifier


class OpenSSLContextHelper:
    @staticmethod
    def get_context(path_to_ca_certs):
        """
            Sets and returns an OpenSSL.context. Notice it sets a flag ont the Cert Store associated to the Context
        """
        context = Context(TLSv1_2_METHOD)
        verify_flags = 0x80000  # partial Chain allowed
        context.set_timeout(3)
        context.set_options(OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_TLSv1)
        context.get_cert_store().set_flags(verify_flags)
        context.load_verify_locations(cafile=None, capath=bytes(path_to_ca_certs, 'utf-8'))
        context.set_verify(VERIFY_PEER, Verifier.verify_cb)
        return context
