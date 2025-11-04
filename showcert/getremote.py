import socket
import certifi
import time
from OpenSSL import SSL
from collections import namedtuple

from .exceptions import ServerError, InvalidAddress

phrase = namedtuple('Phrase', 'say wait expect')

# not covering conversation because it's hard to find server which would produce protocol errors



def recv_until_newline(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Read from socket until '\n' seen or timeout expires."""
    sock.setblocking(False)
    data = bytearray()
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:  # connection closed
                break
            data.extend(chunk)
            if b'\n' in chunk:
                break
        except BlockingIOError:
            time.sleep(0.01)
            continue
    return bytes(data)

def recv_smtp(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """
    Read full SMTP reply (single or multi-line) until final line received or timeout.
    RFC 5321: lines start with 3 digits + ('-' for continuation or ' ' for end).
    """
    sock.setblocking(False)
    data = bytearray()
    lines = []
    deadline = time.monotonic() + timeout
    code = None

    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:  # connection closed
                break
            data.extend(chunk)
            while b'\n' in data:
                line, _, rest = data.partition(b'\n')
                data = bytearray(rest)
                line = line.rstrip(b'\r')
                lines.append(line)

                # parse reply code
                if len(line) >= 4 and line[:3].isdigit():
                    code = line[:3]
                    if line[3:4] == b' ':  # final line
                        return b'\n'.join(lines) + b'\n'
        except BlockingIOError:
            time.sleep(0.01)
            continue

    return b'\n'.join(lines) + b'\n'


def conversation(s, script, read_fn = None):
    verbose = False
    for ph in script:
        if ph.say is not None:
            if verbose:
                print(">", repr(ph.say)) # pragma: no cover
            s.sendall(ph.say.encode())
        if read_fn:
            reply = read_fn(s, timeout=5).decode('utf8')
        else:
            reply = recv_until_newline(s, timeout=5).decode('utf8')

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
    conversation(s, script, read_fn=recv_smtp)

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


def connect46(host, port, limit=5):
    s = None
    for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
            s.settimeout(limit)
            s.connect(sa)
            return s
        except Exception as e:
            if s is not None:
                s.close()
            raise
    

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


    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.settimeout(limit)
    try:
        # s.connect((host, port))
        s = connect46(host, port, limit=limit)
    except Exception as e:
        print(type(e))
        print(e)
        raise

    peername = s.getpeername()
    sock_host = peername[0]
    sock_port = peername[1]

    start_tls(s, starttls, port)
    conn = SSL.Connection(
        context, socket=s
    )
        
    # conn.settimeout(5)
    # conn.connect((host, port))

    conn.setblocking(1)    

    conn.set_tlsext_host_name(name.encode())
    
    conn.set_connect_state()

    try:
        conn.do_handshake()
    except SSL.Error as e:
        # rare case, e.g. RabbitMQ on 5671 which reset connection if client certificate is not sent
        # never happens on webservers
        if insecure and 'ssl/tls alert handshake failure' in str(e):
            print("# Server likely requires a client certificate (handshake failure)")
        else:
            raise
                
    if conn.get_client_ca_list():
        print("# Remote asks for a client certificate")

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
