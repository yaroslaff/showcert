#!/usr/bin/env python

import argparse
import ipaddress
import datetime
import os

from typing import List

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa



from . import __version__


# Gists:
# Create a self-signed x509 certificate with python cryptography library
#     https://gist.github.com/bloodearnest/9017111a313777b9cce5
# Making a certificate authority (CA) with python cryptography
#     https://gist.github.com/major/8ac9f98ae8b07f46b208
#
# https://github.com/ikreymer/certauth/blob/master/certauth/certauth.py


def generate_cert(hostnames: list[str], ip_addresses: list[str] = None, 
                             cakey=None, cacert=None, days=None, bits=None, ca=False):
    """Generates self signed certificate for a hostname, and optional IP addresses."""
    
    # Generate our key
    certkey = rsa.generate_private_key(
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
    
    now = datetime.datetime.utcnow()





    builder = x509.CertificateBuilder() \
        .subject_name(name) \
        .public_key(certkey.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(now) \
        .not_valid_after(now + datetime.timedelta(days=days)) \

    if ca:
        print("Generate CA certificate")
        basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
        builder = builder.add_extension(basic_constraints, True)

#                    crypto.X509Extension(b"basicConstraints",
#                                 True,
#                                b"CA:TRUE, pathlen:0"),

    else:
        basic_constraints = x509.BasicConstraints(ca=True, path_length=0)
        builder = builder.add_extension(basic_constraints, False) \
            .add_extension(san, False)

    # Issuer
    if cacert and cakey:
        builder = builder.issuer_name(cacert.issuer)
    else:
        builder = builder.issuer_name(name)

    # SIGN
    if cakey:
        # sign with CA private key
        cert = builder.sign(private_key=cakey, 
            algorithm=hashes.SHA256(), 
            backend=default_backend())
    else:
        # self-sign
        cert = builder.sign(private_key=certkey, 
            algorithm=hashes.SHA256(), 
            backend=default_backend())
    

    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = certkey.private_bytes(
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

# make simple self-signed cert and key in one file example.com.pem  
gencert example.com www.example.com 


# Your own CA:
# make CA cert and key
gencert --ca  --cert ca.pem --key ca-priv.pem "My CA"

# make host cert and sign CA cert
gencert --cacert ca.pem --cakey ca-priv.pem example.com www.example.com
'''

    parser = argparse.ArgumentParser(
        description=f"gencert version {__version__}",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--cert', help='save new certificate to this file')
    parser.add_argument('--key', help='save private key to this file (optional)')
    parser.add_argument('hostnames', metavar='HOST', nargs='+', help='Hostnames and/or IP addresses')

    g = parser.add_argument_group('CA operations')
    g.add_argument('--ca', default=False, action='store_true', help='Generate --cert/--key for CA, not usual cert')
    g.add_argument('--cakey', metavar='ca.crt', help='read CA key to sign new cert (optional)')
    g.add_argument('--cacert', metavar='file.pem', help='read CA cert to sign new cert (optional)')

    g = parser.add_argument_group('Options')
    g.add_argument('-d', '--days', type=int, metavar='DAYS', default=def_days,
                   help=f'expire in DAYS days ({def_days})')
    g.add_argument('-b', '--bits', type=int, metavar='BITS', default=def_bits,
                   help=f'Key size in bits ({def_bits})')


    parser.epilog = epilog

    return parser.parse_args()

def good_filename(path):
    return path.replace(' ','-')


def change_extension(filename, new_extension):
    base_name, _ = os.path.splitext(filename)
    return base_name + new_extension

def load_privkey(files: List[str]):
    for file in files:
        if file is None:
            continue
        with open(file, 'rb') as fh:
            try:
                privkey = serialization.load_pem_private_key(fh.read(), password=None)
                # print(f"Loaded privkey from {file}")
                return privkey
            except ValueError:
                pass

def main():
    args = get_args()
    ca_privkey = None
    ca_cert = None

    certfile = args.cert
    keyfile = args.key

    if certfile is None:
        certfile = good_filename(args.hostnames[0] + '.pem')
    
    if not keyfile:
        if args.ca:
            # we generate CA certs, key is in different file
            keyfile = change_extension(certfile, '.key')
        else:
            keyfile = certfile

    if args.cacert:
        with open(args.cacert, 'rb') as fh:
            ca_cert = x509.load_pem_x509_certificate(fh.read(), default_backend())


    if args.cacert:
        ca_privkey = load_privkey([args.cakey, args.cacert, change_extension(args.cacert, '.key')])

    #if args.cakey:
    #    with open(args.cakey, 'rb') as fh:
            # ca_privkey = rsa.PrivateKey.load_pkcs1(fh.read())
    #        ca_privkey = serialization.load_pem_private_key(fh.read(), password=None)



    cert, key = generate_cert(hostnames = args.hostnames, 
                                         days=args.days, bits=args.bits,
                                         cakey=ca_privkey, cacert=ca_cert,
                                         ca=args.ca)


    with open(certfile, "wb") as fh:
        fh.write(cert)
        if keyfile == certfile:
            fh.write(key)
    
    if keyfile != certfile:
        # different key file
        with open(keyfile, "wb") as fh:
            fh.write(key)

if __name__ == '__main__':
    main()