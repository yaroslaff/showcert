#!/usr/bin/env python

import argparse
import ipaddress
import datetime
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Gists:
# Create a self-signed x509 certificate with python cryptography library
#     https://gist.github.com/bloodearnest/9017111a313777b9cce5
# Making a certificate authority (CA) with python cryptography
#     https://gist.github.com/major/8ac9f98ae8b07f46b208


def generate_selfsigned_cert(hostnames: list[str], ip_addresses: list[str] = None, 
                             key=None, days=None, bits=None, ca=False):
    """Generates self signed certificate for a hostname, and optional IP addresses."""
    
    # Generate our key
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend(),
        )
    
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])
    ])
 
    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.    
    alt_names = [x509.DNSName(h) for h in hostnames]
    
    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios 
    if ip_addresses:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
    
    san = x509.SubjectAlternativeName(alt_names)
    
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.datetime.utcnow()


    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    print("cert:", cert)
    print(type(cert))



    builder = x509.CertificateBuilder() \
        .subject_name(name) \
        .issuer_name(name) \
        .public_key(key.public_key()) \
        .serial_number(int(uuid.uuid4())) \
        .not_valid_before(now) \
        .not_valid_after(now + datetime.timedelta(days=days)) \
        .add_extension(basic_contraints, False) \
        .add_extension(san, False) \
        .sign(key, hashes.SHA256())
    
    cert = (
        builder, default_backend())
    

    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem

def get_args():

    def_days = 365
    def_bits = 2048

    epilog = '''
Examples:\n

# make self-signed cert and key in one file example.com.pem  
gencert example.com www.example.com 
'''

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--cert', help='certificate file (will be created if missing)')
    parser.add_argument('--key', help='private key file (will be created if missing)')
    parser.add_argument('hostnames', metavar='HOST', nargs='+', help='Hostnames and/or IP addresses')

    g = parser.add_argument_group('CA operations')
    g.add_argument('--ca', default=False, action='store_true', help='Generate --cert/--key for CA, not usual cert')


    g = parser.add_argument_group('Certificate attributes')
    g.add_argument('-a', nargs='+', metavar=('ATTRIBUTE=VALUE'), help='Attribute: OU/O/L/S/C')

    g = parser.add_argument_group('Options')
    g.add_argument('-d', '--days', type=int, metavar='DAYS', default=def_days,
                   help=f'expire in DAYS days ({def_days})')
    g.add_argument('-b', '--bits', type=int, metavar='BITS', default=def_bits,
                   help=f'Key size in bits ({def_bits})')


    parser.epilog = epilog

    return parser.parse_args()

def main():
    args = get_args()
    cert, key = generate_selfsigned_cert(hostnames = args.hostnames, 
                                         days=args.days, bits=args.bits)

    if args.certificate is None:
        args.certificate = args.hostnames[0] + '.pem'

    if args.key and Path(args.key).exists():
        print("load key from", args.key)


    with open(args.certificate, "wb") as fh:
        fh.write(cert)
        if args.key is None:
            fh.write(key)
    
    if args.key and args.key != args.certificate:
        # different key file
        with open(args.key, "wb") as fh:
            fh.write(key)

if __name__ == '__main__':
    main()