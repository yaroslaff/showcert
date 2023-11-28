#!/usr/bin/env python3

from cmath import phase
import os
import sys
import argparse
import re
import ssl
import socket
# import OpenSSL
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_TEXT, load_certificate, \
    dump_certificate, X509Store, X509StoreContext, \
    X509StoreContextError
from OpenSSL import SSL
import pem
import certifi
import glob
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from collections import namedtuple

#import importlib.metadata
#version = importlib.metadata.version("showcert")

__version__ = '0.1.18'


args = None

phrase = namedtuple('Phrase', 'say wait expect')

class CertException(Exception):
    pass

class InvalidCertificate(CertException):
    pass

class ServerError(CertException):
    pass

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
  
    """.format(me=sys.argv[0])
    parser = argparse.ArgumentParser(description='Show local/remote SSL certificate info ver {version}'.format(version=__version__),
    formatter_class=argparse.RawTextHelpFormatter, epilog=epilog)
    parser.add_argument('CERT', nargs='+', help='path, - (stdin), ":le" (letsencrypt cert path), hostname or hostname:port')
    parser.add_argument('-i', '--insecure', default=False, action='store_true', help='Do not verify remote certificate')
    parser.add_argument('--output', '-o', default='brief', help='output format: brief, full, names, dnames (for certbot), pem, no.')
    parser.add_argument('-c','--chain', default=False, action='store_true', help='Show chain (not only server certificate)')
    parser.add_argument('-w', '--warn', default=None, metavar='DAYS', nargs='?', type=int, const=20, help='Warn about expiring certificates (def: 20 days)')

    g = parser.add_argument_group('Rarely needed options')
    g.add_argument('-q', '--quiet', default=False, action='store_true', help='Quiet mode, same as --output no')
    g.add_argument('-n', '--name', help='name for SNI (if not same as CERT host)')
    g.add_argument('-t', '--starttls', default='auto', metavar='METHOD', help='starttls method: auto (default, and OK almost always), no, imap, smtp, pop3')
    g.add_argument('-l', '--limit', default=def_limit, type=int, metavar='TIME', help='socket timeout (def: {})'.format(def_limit))
    g.add_argument('--ca', default=def_ca, help="path to trusted CA certificates, def: {}".format(def_ca))
    g.add_argument('--net', default=False, action='store_true',
                   help="Force network check (if you want to check host and have file/dir with same name in current directory)")

    return parser.parse_args()


def conversation(s, script):
    verbose = False
    for ph in script:
        if ph.say is not None:
            if verbose:
                print(">", repr(ph.say))
            s.sendall(ph.say.encode())
        reply = s.recv(2048).decode('utf8')
        if verbose:
            print("<", repr(reply))
            print("wait:", repr(ph.wait))
        if ph.wait is not None and ph.wait not in reply:
            raise ServerError('Not found {!r} in server reply {!r} to {!r}'.format(ph.wait, reply, ph.say))
        if ph.expect is not None and ph.expect not in reply:
            raise ServerError('Not found {!r} in server reply {!r} to {!r}'.format(ph.expect, reply, ph.say))
        if verbose:
            print("got it")

def starttls_imap(s):
    script = (
        phrase(None, '\n', None),
        phrase('a1 CAPABILITY\r\n', '\n', 'STARTTLS'),
        phrase('a2 STARTTLS\r\n','\n', None)
    )
    conversation(s, script)

def starttls_smtp(s):
    script = (
        phrase(None, '\n', None),
        phrase('EHLO www-security.com\n', '\n', 'STARTTLS'),
        phrase('STARTTLS\n','\n', None)
    )
    conversation(s, script)

def starttls_pop3(s):
    script = (
        phrase(None, '\n', None),
        phrase('STLS\n', '\n', None),
    )
    conversation(s, script)


def start_tls(s, method, port):

    port2method_map = {
        25: 'smtp',
        110: 'pop3',
        143: 'imap'
    }

    method_map ={
        'imap': starttls_imap,
        'smtp': starttls_smtp,
        'pop3': starttls_pop3
    }

    if method == 'no':
        return

    if method == 'auto':
        try:
            method = port2method_map[port]
        except KeyError:
            # no special handling needed
            return

    return method_map[method](s)



def get_certificate_chain(host, name=None, port=443, timeout=10, insecure=False, starttls='auto'):
    
    name = name or host
    context = SSL.Context(method=SSL.TLS_CLIENT_METHOD)
    
    if insecure:
        context.set_verify(SSL.VERIFY_NONE)
    else:
        context.set_verify(SSL.VERIFY_PEER)
        context.load_verify_locations(cafile=args.ca)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.limit)
    s.connect((host, port))

    sock_host, sock_port = s.getpeername()
    
    start_tls(s, args.starttls, port)

    conn = SSL.Connection(
        context, socket=s
    )
        
    # conn.settimeout(5)
    # conn.connect((host, port))
    conn.setblocking(1)

    conn.set_tlsext_host_name(name.encode())
    
    conn.set_connect_state()
    conn.do_handshake()

    chain = conn.get_peer_cert_chain()
    return sock_host, chain


def is_local(cert, net):
    """ guesses is cert is local file or not """
    if net:
        return False

    if os.path.exists(cert) and os.path.isfile(cert) or cert == '-':
        return True
    return False


def get_remote_certs(location, name=None, insecure=False, starttls='auto'):
    # parse CERT address

    services = {
        'http': 80,
        'https': 443,
        'pop3': 110,
        'pop3s': 995,
        'imap': 143,
        'imap2': 143,
        'imaps': 993,
        'smtp': 25,
        'submissions': 465
    }

    if ':' in location:
        (host, port) = location.split(':')
    else:
        host = location
        port = 443
    
    name = name or host

    try:
        port = services[port]
    except KeyError:
        port = int(port)

    certlist = get_certificate_chain(host, name=name, port=port, insecure=insecure, starttls=starttls)
    
    # cert = load_certificate(FILETYPE_PEM, certificate)
    return certlist

def get_local_certs(CERT, insecure=False):
    if CERT == '-':
        rawcert = sys.stdin.read().encode()
    else:        
        rawcert = open(CERT).read().encode()


    # raw_ca = open(args.ca).read().rstrip().encode()

    return [ load_certificate(FILETYPE_PEM, str(_c)) for _c in pem.parse(rawcert) if _c.__class__.__name__ == 'Certificate' ]

def verify_chain(chain, hostname=None):

    # verify
    store = X509Store()

    raw_ca = open(args.ca).read().rstrip().encode()

    for _ca in pem.parse(raw_ca):
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

        names = get_names(chain[0])
        for _n in names:
            if _n == hostname or _n == wildcard_hostname:
                return

        # not found
        raise InvalidCertificate('{} not found in {}'.format(hostname, ' '.join(names)))



def get_days_left(crt):
    nafter = datetime.strptime(crt.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
    left = (nafter - datetime.now()).days
    return left

def get_names(crt):


    def tlist2value(tlist, key):
        for t in tlist:
            if t[0].decode() == key:
                return t[1].decode()

    def get_SAN(cert):

        def safestr(x):
            try:
                return str(x)
            except:
                return ''

        extensions = (cert.get_extension(i) for i in range(cert.get_extension_count()))

        extension_data = {e.get_short_name().decode(): safestr(e) for e in extensions}

        try:
            return [ n.split(':')[1] for n in extension_data['subjectAltName'].split(',') ]
        except KeyError:
            return [] # No subjectAltName
        except IndexError:
            raise InvalidCertificate('Unusual certificate, cannot parse SubjectAltName')

    subject = tlist2value(crt.get_subject().get_components(), 'CN')
    names = get_SAN(crt)

    if subject in names:
        names.remove(subject)
    
    if subject:
        # add only if Subject exists (yes, not always)
        names.insert(0, subject)
    return names


def print_full_cert(crt):
    print(dump_certificate(FILETYPE_TEXT, crt).decode())

def print_names(crt):
    names = get_names(crt)

    print(' '.join(names))


def print_dnames(crt):
    names = get_names(crt)
    print('-d', ' -d '.join(names))


def print_cert(crt, addr=None):

    def tlist2str(tlist):
        return ' '.join([ '{}={}'.format(t[0].decode(), t[1].decode()) for t in tlist ])

    nbefore = datetime.strptime(crt.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
    nafter = datetime.strptime(crt.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
    daysold = (datetime.now() - nbefore).days
    daysleft = (nafter - datetime.now()).days
    issuer = tlist2str(crt.get_issuer().get_components())

    names = get_names(crt)

    if addr:
        print("IP:", addr)
    print("Names:", ' '.join(names))
    print("notBefore: {nbefore} ({days} days old)".format(nbefore=nbefore, days=daysold))
    print("notAfter: {nafter} ({days} days left)".format(nafter=nafter, days = daysleft))
    print("Issuer:", issuer)

def process_cert(CERT, name=None, insecure=False, warn=False, starttls='auto'):

    retcode = 0
    hostname = None
    out = args.output.lower()
    sock_host = None

    try:
        if is_local(CERT, args.net):
            chain = get_local_certs(CERT)
            if not chain:
                raise InvalidCertificate('Can not load certificate from file '+ CERT + '\nUse option --net if you want to check host ' + CERT)

        else:
            hostname = name or CERT.split(':')[0]
            sock_host, chain = get_remote_certs(location=CERT, name=name, insecure=insecure, starttls=starttls)
    except SSL.Error as e:
        print("{CERT} Certificate verification error (use -i): {exception}".format(CERT=CERT, exception=e),
            file=sys.stderr)
        return 1
    except socket.timeout as e:
        print("Timeout connecting to {}".format(CERT), file=sys.stderr)
        return 1
    except socket.gaierror as e:
        print("Error with {}: {}".format(CERT, e), file=sys.stderr)
        return 1


    if not args.insecure:
        try:
            verify_chain(chain, hostname)
        except X509StoreContextError as e:
            print("Verification error (use -i):", e.args[0])
            return 1
        except InvalidCertificate as e:
            print("Verification error (use -i):", e)
            return 1

    if not args.chain:
        chain = chain[0:1]


    # set retcode
    left = get_days_left(chain[0])
    if args.warn is not None and left<args.warn:
        print("{CERT} expires in {left} days".format(CERT=CERT, left=left),
            file=sys.stderr)
        retcode = 2


    # output
    if out == 'raw' or out == 'pem':
        for _c in chain:
            r = dump_certificate(FILETYPE_PEM, _c)
            print(r.decode(), end='')
        return 0
    elif out == 'brief':
        for i,_c in enumerate(chain):
            if i>0:
                print()
            print_cert(_c, addr=sock_host)

    elif out == 'full':
        for i,_c in enumerate(chain):
            if i>0:
                print()
            print_full_cert(_c)
    
    elif out == 'names':
        for i,_c in enumerate(chain):
            if i>0:
                print()
            print_names(_c)

    elif out == 'dnames':
        for i,_c in enumerate(chain):
            if i>0:
                print()
            print_dnames(_c)

    elif out == 'no' or out[0] == 'quiet':
        pass

    else:
        print("unknown output (-o) format", file=sys.stderr)

    return retcode


def main():
    
    global args 
    args = get_args()

    # argument parsing sugar
    if args.quiet:
        args.output = 'no'

    if ':le' in args.CERT:
        args.CERT = glob.glob('/etc/letsencrypt/live/*/fullchain.pem')
    
    maxrc = 0
    for cert in args.CERT:
        try:
            rc = process_cert(CERT=cert, name=args.name, insecure=args.insecure, warn=args.warn, starttls=args.starttls)
            maxrc = max(maxrc, rc)
        except CertException as e:
            print("{}: {}".format(cert, e))
            maxrc=1
    sys.exit(maxrc)


if __name__ == '__main__':
    main()
    
