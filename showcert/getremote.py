import socket
import certifi
import time
from OpenSSL import SSL
from collections import namedtuple

from .exceptions import ServerError, InvalidAddress

phrase = namedtuple('Phrase', 'say wait expect')

# not covering conversation because it's hard to find server which would produce protocol errors

def conversation(s, script):
    verbose = False
    for ph in script:
        if ph.say is not None:
            if verbose:
                print(">", repr(ph.say)) # pragma: no cover
            s.sendall(ph.say.encode())
        reply = s.recv(2048).decode('utf8')
        if verbose:
            print("<", repr(reply))  # pragma: no cover
            print("wait:", repr(ph.wait)) # pragma: no cover
        if ph.wait is not None and ph.wait not in reply: # pragma: no cover
            raise ServerError('Not found {!r} in server reply {!r} to {!r}'.format(ph.wait, reply, ph.say)) # pragma: no cover
        if ph.expect is not None and ph.expect not in reply: # pragma: no cover
            raise ServerError('Not found {!r} in server reply {!r} to {!r}'.format(ph.expect, reply, ph.say)) # pragma: no cover
        if verbose:
            print("got it") # pragma: no cover

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
    else:
        if method not in method_map:
            raise ValueError('Unknown starttls method {!r}'.format(method))

    return method_map[method](s)


def get_certificate_chain(host, name=None, port=443, insecure=False, starttls='auto', 
                          trusted_ca=None, limit=3):
    
    name = name or host
    context = SSL.Context(method=SSL.TLS_CLIENT_METHOD)

    trusted_ca = trusted_ca or certifi.where()

    if insecure:
        context.set_verify(SSL.VERIFY_NONE)
    else:
        context.set_verify(SSL.VERIFY_PEER)
        context.load_verify_locations(trusted_ca)


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(limit)    
    s.connect((host, port))


    sock_host, sock_port = s.getpeername()
    
    start_tls(s, starttls, port)

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


def get_remote_certs(remote, name=None, insecure=False, starttls='auto', trusted_ca = None, limit = None):
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

    if ':' in remote:
        try:
            (host, port) = remote.split(':')
        except ValueError:
            raise InvalidAddress('Invalid remote address. Valid examples: github.com or smtp.google.com:25')
    else:
        host = remote
        port = 443
    
    name = name or host

    try:
        port = services[port]
    except KeyError:
        try:
            port = int(port)
        except ValueError:
            raise InvalidAddress('Invalid remote address. Valid examples: github.com or smtp.google.com:25')

    certlist = get_certificate_chain(host, name=name, port=port, insecure=insecure, 
                                     starttls=starttls, trusted_ca=trusted_ca, limit=limit)
    
    # cert = load_certificate(FILETYPE_PEM, certificate)
    return certlist
