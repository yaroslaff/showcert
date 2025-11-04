from showcert import process_cert
from unittest import mock
import io

class TestShowcertLocal():

    showcert = 'showcert'
    gencert = 'gencert'
    snakeoil = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
    ca_certs = [ '/etc/ssl/certs/DigiCert_Global_Root_CA.pem', '/etc/ssl/certs/Amazon_Root_CA_1.pem', '/etc/ssl/certs/Amazon_Root_CA_2.pem']

    def test_snakeoil(self):
        rc = process_cert(CERT=self.snakeoil)
        assert(rc == 1)

        rc = process_cert(CERT=self.snakeoil, insecure=True)
        assert(rc == 0)

    def test_snakeoil_output(self):
        rc = process_cert(CERT=self.snakeoil, output='no', insecure=True)
        assert(rc == 0)

        rc = process_cert(CERT=self.snakeoil, output='nosuchformat', insecure=True)
        assert(rc == 0)


    def test_ca(self):
        for ca in self.ca_certs:
            print("test:", ca)
            rc = process_cert(CERT=ca)
            assert(rc == 0)

    def test_print(self):
        rc = process_cert(CERT=self.ca_certs[0], output='full')
        assert(rc == 0)
        rc = process_cert(CERT=self.ca_certs[0], output='ext')
        assert(rc == 0)
        rc = process_cert(CERT=self.snakeoil, output='names', insecure=True)
        assert(rc == 0)
        rc = process_cert(CERT=self.snakeoil, output='dnames', insecure=True)
        assert(rc == 0)
        rc = process_cert(CERT=self.snakeoil, output='pem', insecure=True)
        assert(rc == 0)
        rc = process_cert(CERT=self.snakeoil, output='no', insecure=True)
        assert(rc == 0)

    def test_stdin(self):        
        with open(self.ca_certs[0], "r") as f:  # Read the certificate file
            mock_input = f.read()
        with mock.patch("sys.stdin", io.StringIO(mock_input)):
            rc = process_cert(CERT='-')
            assert rc == 0
