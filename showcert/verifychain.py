from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from OpenSSL.crypto import X509Store, X509StoreContext
import certifi
import pem

from .printcert import get_names_openssl
from .exceptions import InvalidCertificate

def verify_chain(chain, hostname=None, trusted_ca = None):

    trusted_ca = trusted_ca or certifi.where()

    # verify
    store = X509Store()

    raw_ca = open(trusted_ca).read().rstrip().encode()

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
        wildcard_hostname = '*.' + hostname.split('.',1)[1]

        names = get_names_openssl(chain[0])
        for _n in names:
            if _n == hostname or _n == wildcard_hostname:
                return

        # not found
        raise InvalidCertificate('{} not found in {}'.format(hostname, ' '.join(names)))

