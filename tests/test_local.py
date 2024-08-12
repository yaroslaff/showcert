import subprocess

class TestShowcertLocal():

    showcert = 'showcert'
    gencert = 'gencert'
    snakeoil = '/etc/ssl/certs/ssl-cert-snakeoil.pem'

    def test_snakeoil(self):
        rc = subprocess.run([self.showcert, self.snakeoil])
        assert(rc.returncode == 1)

        rc = subprocess.run([self.showcert, '-i', self.snakeoil])
        assert(rc.returncode == 0)

    def test_gencert(self, tmp_path):
        ca_path = tmp_path / 'ca.pem'
        ca_key_path = tmp_path / 'ca-priv.pem'
        
        # make CA cert
        rc = subprocess.run([self.gencert, '--ca', '--cert', ca_path, '--key', ca_key_path, 'My CA'])  
        assert(rc.returncode == 0)

        # sign cert
        cert_path = tmp_path / 'cert.pem'
        rc = subprocess.run([self.gencert, '--cacert', ca_path, '--cakey', ca_key_path, 
                             '--cert', cert_path,
                             'example.com', 'www.example.com'])  
        assert(rc.returncode == 0)
 
        # must be failed because self-signed
        rc = subprocess.run([self.showcert, cert_path])
        assert(rc.returncode == 1)

        rc = subprocess.run([self.showcert, '-i', cert_path])
        assert(rc.returncode == 0)

        rc = subprocess.run([self.showcert, cert_path, '--ca', ca_path])
        assert(rc.returncode == 0)
