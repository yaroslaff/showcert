from showcert.cli.gencert_main import generate_cert, save_key
from showcert import process_cert
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import os

class TestGencert():
    path: Path

    def setup_class(self):
        tmp_path = Path(f"/tmp/ca-{os.getpid()}")
        tmp_path.mkdir()

        # print("method:", method)
        
        self.path = tmp_path

        self.ca_cert_path = self.path / 'ca.pem'
        self.ca_key_path = self.path / 'ca-priv.pem'
        self.cert_path = self.path / 'example.pem'
        self.key_path = self.path / 'example-priv.pem'
        self.badchain_path = self.path / 'badchain.pem'

        
        cacert, cakey = generate_cert(["Test CA"], ca=True, days=1)
        with open(self.ca_cert_path, "wb") as fh:
            fh.write(cacert.public_bytes(encoding=serialization.Encoding.PEM))        
        with open(self.ca_key_path, "wb") as fh:
            save_key(fh, cakey)

        self.cacert = cacert
        self.cakey = cakey

        cert, key = generate_cert(["example.com", "www.example.com"], cakey=self.cakey, cacert=self.cacert)
        with open(self.cert_path, "wb") as fh:
            fh.write(cert.public_bytes(encoding=serialization.Encoding.PEM))        
        with open(self.key_path, "wb") as fh:
            save_key(fh, key)

        badchain, _ = generate_cert(["example.com", "www.example.com"], cakey=self.cakey, cacert=self.cacert)
        with open(self.badchain_path, "wb") as fh:
            fh.write(badchain.public_bytes(encoding=serialization.Encoding.PEM))
            fh.write(cert.public_bytes(encoding=serialization.Encoding.PEM))        


    def test_certs(self):

        rc = process_cert(CERT=self.cert_path)
        assert(rc == 1)

        rc = process_cert(CERT=self.cert_path, insecure=True)
        assert(rc == 0)

        rc = process_cert(CERT=self.cert_path, trusted_ca=self.ca_cert_path)
        assert(rc == 0)

    def test_badchain(self):
        rc = process_cert(CERT=self.badchain_path)
        assert(rc == 1)        

    def teardown_class(self):        
        self.ca_cert_path.unlink()
        self.ca_key_path.unlink()
        self.cert_path.unlink()
        self.key_path.unlink()
        self.badchain_path.unlink()
        self.path.rmdir()

