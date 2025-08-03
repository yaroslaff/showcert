from showcert import process_cert
from OpenSSL import SSL

import pytest

class TestClient:
    def test_client(self):
        srv = "client.badssl.com"
        process_cert(srv)

    def test_handshake_failure(self, monkeypatch):
        def fake_handshake(self):
            original_handshake(self)
            raise SSL.Error([('SSL routines', '', 'ssl/tls alert handshake failure')])

        original_handshake = SSL.Connection.do_handshake
        monkeypatch.setattr("OpenSSL.SSL.Connection.do_handshake", fake_handshake)
        process_cert("client.badssl.com", insecure=True)

