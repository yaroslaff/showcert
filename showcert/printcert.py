from datetime import datetime
from cryptography import x509
from OpenSSL.crypto import X509, dump_certificate, FILETYPE_TEXT
from typing import List, Optional


from .utils import convert_openssl_to_cryptography
from .exceptions import InvalidCertificate


def get_extension_value(cert: x509.Certificate, oid):
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
        return ext.value
    except x509.ExtensionNotFound:
        return None


def get_names_openssl(crt: X509):
    crt_crypto = convert_openssl_to_cryptography(crt)
    return get_names(crt_crypto)



def get_cn(crt: x509.Certificate):
    for attribute in crt.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:  # Check if the attribute is CN
            return attribute.value

def get_names(crt: x509.Certificate) -> List[str]:
    """ return CN subject of certificate + all DNS names in SAN extension """

    names = list()
    cn = get_cn(crt)
    if cn:
        names.append(cn)

    SAN = get_extension_value(crt, x509.OID_SUBJECT_ALTERNATIVE_NAME)
    if SAN is None:
        return names
    names.extend([name.value for name in SAN if isinstance(name, x509.DNSName)])
    return names

def is_self_signed(crt: x509.Certificate):
    return crt.issuer == crt.subject

def is_CA(crt: x509.Certificate):
    # Get the extensions from the certificate
    extensions = crt.extensions

    # Look for the BasicConstraints extension
    basic_constraints = next((ext.value for ext in extensions if isinstance(ext.value, x509.BasicConstraints)), None)

    # If BasicConstraints is not present, or if it is present and CA is set to True, it is a CA certificate
    return basic_constraints is None or basic_constraints.ca

def is_EV(crt: x509.Certificate) -> bool:
    EV_OIDS = ['2.23.140.1.1']
    try:
        policies = crt.extensions.get_extension_for_class(x509.CertificatePolicies).value
        for policy in policies:
            if policy.policy_identifier.dotted_string in EV_OIDS:
                return True  # Found a policy OID that matches a known EV OID

    except x509.ExtensionNotFound:
        # No certificate policies extension found
        pass
    
    return False


def print_full_cert(crt):
    print(dump_certificate(FILETYPE_TEXT, crt).decode())

def print_names(crt: X509):
    # expects openssl crt!
    cc = convert_openssl_to_cryptography(crt)
    names = get_names(cc)

    print(' '.join(names))

def print_dnames(crt):
    cc = convert_openssl_to_cryptography(crt)
    names = get_names(cc)
    print('-d', ' -d '.join(names))

def hexify(b: bytes) -> str:
    hex_string = b.hex()
    return ":".join(hex_string[i:i+2] for i in range(0, len(hex_string), 2)).upper()

def print_cert(crt: X509, fmt='brief', addr=None, path=None, verified=False):

    def tlist2str(tlist):
        return ' '.join([ '{}={}'.format(t[0].decode(), t[1].decode()) for t in tlist ])

    tags = list()

    crypto_crt = convert_openssl_to_cryptography(crt)

    if is_self_signed(crypto_crt):
        tags.append('[SELF-SIGNED]')

    if is_CA(crypto_crt):
        tags.append('[CA]')

    if is_EV(crypto_crt):
        tags.append('[EV]')

    if verified:
        tags.append('[CHAIN-VERIFIED]')


    nbefore = datetime.strptime(crt.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
    nafter = datetime.strptime(crt.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
    daysold = (datetime.now() - nbefore).days
    daysleft = (nafter - datetime.now()).days
    issuer = tlist2str(crt.get_issuer().get_components())
    fingerprint = crt.digest("sha256").decode("utf-8")

    #ski = crt.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER) \
    #    .value.digest.hex()


    subject_key_id = get_extension_value(crypto_crt, x509.OID_SUBJECT_KEY_IDENTIFIER)
    authority_key_id = get_extension_value(crypto_crt, x509.OID_AUTHORITY_KEY_IDENTIFIER)

    names = get_names(crypto_crt)

    if addr:
        print("IP:", addr)
    if path:
        print("Path:", path)
    print("Names:", ' '.join(names))
    print("notBefore: {nbefore} ({days} days old)".format(nbefore=nbefore, days=daysold))
    print("notAfter: {nafter} ({days} days left)".format(nafter=nafter, days = daysleft))
    print("Issuer:", issuer)

    if fmt.startswith('ext'):
        print("Fingerprint (sha256):", fingerprint)
        if subject_key_id:
            print("Subject KI:", hexify(subject_key_id.digest))
        if authority_key_id:
            print("Authority KI:", hexify(authority_key_id.key_identifier))

    if tags:
        print("Tags:", ' '.join(tags))
