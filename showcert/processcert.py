from datetime import datetime
import os
import sys

from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_TEXT, load_certificate, \
    dump_certificate, X509, X509Store, X509StoreContext, \
    X509StoreContextError
from OpenSSL import SSL
import pem
import socket

from .getremote import get_remote_certs
from .exceptions import CertException, InvalidCertificate
from .verifychain import verify_chain
from .printcert import print_cert, print_full_cert, print_dnames, print_names



def is_local(cert, net):
    """ guesses is cert is local file or not """
    if net:
        return False

    if os.path.exists(cert) and os.path.isfile(cert) or cert == '-':
        return True
    return False



def get_local_certs(CERT, insecure=False):
    if CERT == '-':
        rawcert = sys.stdin.read().encode()
    else:        
        rawcert = open(CERT).read().encode()


    # raw_ca = open(args.ca).read().rstrip().encode()

    return [ load_certificate(FILETYPE_PEM, str(_c)) for _c in pem.parse(rawcert) if _c.__class__.__name__ == 'Certificate' ]


def get_days_left(crt):
    nafter = datetime.strptime(crt.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
    left = (nafter - datetime.now()).days
    return left



def process_cert(CERT, name=None, insecure=False, warn=None, starttls='auto', output='brief',
                 force_network=False, trusted_ca=None, limit=None, chain=False):

    retcode = 0
    hostname = None
    out = output.lower()
    sock_host = None
    path = None
    verified = None

    try:
        if is_local(CERT, force_network):
            cert_chain = get_local_certs(CERT)
            path = CERT
            if not cert_chain:
                raise InvalidCertificate('Can not load certificate from file '+ CERT + '\nUse option --net if you want to check host ' + CERT)

        else:
            hostname = name or CERT.split(':')[0]
            sock_host, cert_chain = get_remote_certs(remote=CERT, name=name, insecure=insecure, 
                                                starttls=starttls, trusted_ca=trusted_ca, limit=limit)
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


    if not insecure:
        try:
            verify_chain(cert_chain, hostname, trusted_ca=trusted_ca)
            verified = True
        except X509StoreContextError as e:
            print("Verification error (use -i):", e.args[0])
            return 1
        except InvalidCertificate as e:
            print("Verification error (use -i):", e)
            return 1


    if not chain:
        cert_chain = cert_chain[0:1]


    # set retcode
    left = get_days_left(cert_chain[0])
    if warn is not None and left<warn:
        print("{CERT} expires in {left} days".format(CERT=CERT, left=left),
            file=sys.stderr)
        retcode = 2


    # output
    if out == 'raw' or out == 'pem':
        for _c in cert_chain:
            r = dump_certificate(FILETYPE_PEM, _c)
            print(r.decode(), end='')
        return 0
    elif out in ['brief', 'ext', 'extended']:
        for i,_c in enumerate(cert_chain):
            if i>0:
                print()
            print_cert(crt = _c, fmt=out, addr=sock_host, path=path, verified=verified)

    elif out == 'full':
        for i,_c in enumerate(cert_chain):
            if i>0:
                print()
            print_full_cert(_c)
    
    elif out == 'names':
        for i,_c in enumerate(cert_chain):
            if i>0:
                print()
            print_names(_c)

    elif out == 'dnames':
        for i,_c in enumerate(cert_chain):
            if i>0:
                print()
            print_dnames(_c)

    elif out == 'no' or out[0] == 'quiet':
        pass

    else:
        print("unknown output (-o) format", file=sys.stderr)

    return retcode

