#!/usr/bin/env python3

from cmath import phase
import os
import sys
import argparse
import re
import hashlib
import ssl
import socket
# import OpenSSL
import certifi
import glob
from datetime import datetime
from cryptography import x509

from urllib.parse import urlparse

from ..__about__ import __version__
from ..getremote import get_remote_certs
from ..exceptions import CertException, InvalidCertificate
from ..verifychain import verify_chain
from ..printcert import print_cert, print_full_cert, print_dnames, print_names
from ..processcert import process_cert

#import importlib.metadata
#version = importlib.metadata.version("showcert")

# do not  use CLI args globally
# args = None

def fix_cert(url: str) -> str:
    """ if https url: translate it to host """
    parsed = urlparse(url)    
    return parsed.hostname or url

def get_args():
    def_ca = certifi.where()
    def_limit = 5

    epilog = """Examples:  
  # just check remote certificate
  {me} example.com

  # check SMTP server certificate (autodetected: --starttls smtp )
  {me} smtp.google.com:25

  # save fullchain from google SMTP to local PEM file
  {me} --chain -o pem google.com > google-fullchain.pem
  
  # look for expiring letsencrypt certificates 
  # :le is alias for /etc/letsencrypt/live/*/fullchain.pem 
  {me} :le -q -w 20 || echo "expiring soon!"
  
    """.format(me='showcert')


    parser = argparse.ArgumentParser(description='Show local/remote SSL certificate info ver {version}'.format(version=__version__),
    formatter_class=argparse.RawTextHelpFormatter, epilog=epilog)
    parser.add_argument('CERT', nargs='+', help='path, - (stdin), ":le" (letsencrypt cert path), hostname or hostname:port')
    parser.add_argument('-i', '--insecure', default=False, action='store_true', help='Do not verify remote certificate')
    parser.add_argument('--output', '-o', choices=['brief', 'ext', 'full', 'names', 'dnames', 'pem', 'no'], default='brief', help='output format')
    parser.add_argument('-c','--chain', default=False, action='store_true', help='Show chain (not only server certificate)')
    parser.add_argument('-w', '--warn', default=None, metavar='DAYS', nargs='?', type=int, const=20, help='Warn about expiring certificates (def: 20 days)')
    parser.add_argument('-p', '--password', default=None, metavar='PASSWORD', help='Password (for PKCS#12 certificates)')

    g = parser.add_argument_group('Rarely needed options')
    g.add_argument('-q', '--quiet', default=False, action='store_true', help='Quiet mode, same as --output no')
    g.add_argument('-n', '--name', help='name for SNI (if not same as CERT host)')
    g.add_argument('-t', '--starttls', default='auto', metavar='METHOD', help='starttls method: auto (default, and OK almost always), no, imap, smtp, pop3')
    g.add_argument('-l', '--limit', default=def_limit, type=int, metavar='TIME', help='socket timeout (def: {})'.format(def_limit))
    g.add_argument('--ca', default=def_ca, help="path to trusted CA certificates, def: {}".format(def_ca))
    g.add_argument('--net', default=False, action='store_true',
                   help="Force network check (if you want to check host and have file/dir with same name in current directory)")

    return parser.parse_args()

def main():
    
    # global args 
    args = get_args()

    output = args.output if not args.quiet else 'no'


    if ':le' in args.CERT:
        args.CERT = glob.glob('/etc/letsencrypt/live/*/fullchain.pem')
    
    maxrc = 0
    for cert in args.CERT:
        try:
            rc = process_cert(
                CERT=fix_cert(cert), 
                name=args.name, 
                insecure=args.insecure, 
                warn=args.warn, 
                starttls=args.starttls,
                output=output,
                force_network=args.net,
                trusted_ca=args.ca,
                chain=args.chain,
                limit=args.limit,
                password=args.password)
            maxrc = max(maxrc, rc)
        except (CertException, ValueError) as e:
            print("{}: {}".format(cert, e))
            maxrc=1
    return(maxrc)


if __name__ == '__main__':
    sys.exit(main())
    
