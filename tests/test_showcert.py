import subprocess

class TestShowcert():

    showcert = 'bin/showcert'
    snakeoil = '/etc/ssl/certs/ssl-cert-snakeoil.pem'

    sites = [ 'github.com', 'okerr.com', 'www-security.com', 'gmail.com' ]
    wildcard_sites = [ 'www.badssl.com' ]
    badssl_sites = ['expired.badssl.com', 'wrong.host.badssl.com', 'self-signed.badssl.com', 'untrusted-root.badssl.com']
    pop3_sites = ['pop.yandex.ru:110']
    pop3s_sites = ['pop.yandex.ru:995', 'pop.gmail.com:995']
    imap_sites = ['imap.yandex.ru:143']
    imaps_sites = ['imap.yandex.ru:993', 'imap.gmail.com:993']

    def test_snakeoil(self):
        rc = subprocess.run([self.showcert, self.snakeoil])
        assert(rc.returncode == 1)

        rc = subprocess.run([self.showcert, '-i', self.snakeoil])
        assert(rc.returncode == 0)


    def test_https(self):
        for site in self.sites:
            print("test site {}".format(site))
            rc = subprocess.run([self.showcert, site])        
            assert(rc.returncode == 0)

    def test_https_warn(self):
        for site in self.sites:
            print("test site {}".format(site))
            rc = subprocess.run([self.showcert, '-w', '2000', site])        
            assert(rc.returncode == 2)

    def test_wildcard(self):
        for site in self.wildcard_sites:
            rc = subprocess.run([self.showcert, site])        
            assert(rc.returncode == 0)

    def test_badssl(self):
        for site in self.badssl_sites:
            print(site)
            rc = subprocess.run([self.showcert, site])        
            assert(rc.returncode == 1)

    def test_badssl_ignore(self):
        for site in self.badssl_sites:
            print(site)
            rc = subprocess.run([self.showcert, "-i", site])        
            assert(rc.returncode == 0)



    def test_pop3(self):
        for site in self.pop3_sites:
            print(site)
            rc = subprocess.run([self.showcert, site])
            assert(rc.returncode == 0)

    def test_pop3s(self):
        for site in self.pop3s_sites:
            print(site)
            rc = subprocess.run([self.showcert, site])
            assert(rc.returncode == 0)

    def test_imap(self):
        for site in self.imap_sites:
            print(site)
            rc = subprocess.run([self.showcert, site])
            assert(rc.returncode == 0)

    def test_imaps(self):
        for site in self.imaps_sites:
            print(site)
            rc = subprocess.run([self.showcert, site])
            assert(rc.returncode == 0)
            