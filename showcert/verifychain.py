from pathlib import Path

from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from OpenSSL.crypto import X509Store, X509StoreContext
import certifi
import pem

from .printcert import get_names_openssl
from .exceptions import InvalidCertificate


def wildcard_match(host: str, pattern: str) -> bool:
    if pattern.startswith('*.') and '.' in host:
        #wildcard comparison
        host_right = host.split('.', 1)[1]
        pattern_right = pattern.split('.',1)[1]
        return host_right == pattern_right        
    else:        
        return host == pattern

def verify_chain(chain, hostname=None, trusted_ca = None):

    trusted_ca = trusted_ca or certifi.where()

    # verify
    store = X509Store()

    raw_ca = Path(trusted_ca).read_bytes().rstrip()

    for _ca in pem.parse(raw_ca):
        if isinstance(_ca, pem._object_types.Certificate):
            store.add_cert(load_certificate(FILETYPE_PEM, str(_ca)))

    # verify and add each intermediate cert
    for _i in reversed(chain[1:]):
        
        _sctx = X509StoreContext(store, _i)
        try:
            _sctx.verify_certificate()
            store.add_cert(_i)
        except Exception as e:
            pass

    
    store_ctx = X509StoreContext(store, chain[0])
    store_ctx.verify_certificate()

    if hostname:

        names = get_names_openssl(chain[0])
        for _n in names:
            if wildcard_match(hostname, _n):
                return

        # not found
        raise InvalidCertificate('{} not found in {}'.format(hostname, ' '.join(names)))

