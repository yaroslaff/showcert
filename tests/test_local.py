from showcert import process_cert

class TestShowcertLocal():

    showcert = 'showcert'
    gencert = 'gencert'
    snakeoil = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
    ca_certs = ['/etc/ssl/certs/Go_Daddy_Class_2_CA.pem', '/etc/ssl/certs/Amazon_Root_CA_2.pem']

    def test_snakeoil(self):
        rc = process_cert(CERT=self.snakeoil)
        assert(rc == 1)

        rc = process_cert(CERT=self.snakeoil, insecure=True)
        assert(rc == 0)

    def test_ca(self):
        for ca in self.ca_certs:
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
