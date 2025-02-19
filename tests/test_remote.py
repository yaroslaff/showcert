import time
from showcert import process_cert

class TestShowcertRemote():

    showcert = 'showcert'

    sites = [ 'github.com', 'okerr.com', 'www-security.com', 'gmail.com' ]
    wildcard_sites = [ 'www.badssl.com' ]
    badssl_sites = ['expired.badssl.com', 'wrong.host.badssl.com', 'self-signed.badssl.com', 'untrusted-root.badssl.com']
    pop3_sites = ['pop.yandex.ru:110']
    pop3s_sites = ['pop.yandex.ru:995', 'pop.gmail.com:995']
    imap_sites = ['imap.yandex.ru:143']
    imaps_sites = ['imap.yandex.ru:993', 'imap.gmail.com:993']

    def test_https(self):
        for site in self.sites:
            print("test site {}".format(site))
            code = process_cert(CERT=site)
            assert code == 0

    def test_https_warn(self):
        for site in self.sites:
            # warn if expires "too soon" in 2000 days
            code = process_cert(CERT=site, warn=2000)
            assert code == 2

    def test_wildcard(self):
        for site in self.wildcard_sites:
            code = process_cert(CERT=site)
            assert code == 0

    def test_badssl(self):
        for site in self.badssl_sites:
            code = process_cert(CERT=site)
            assert code == 1

    def test_badssl_ignore(self):
        for site in self.badssl_sites:
            code = process_cert(CERT=site, insecure=True)
            assert code == 0

    def test_pop3(self):
        for site in self.pop3_sites:
            code = process_cert(CERT=site)
            assert code == 0

    def test_pop3s(self):
        for site in self.pop3s_sites:
            code = process_cert(CERT=site)
            assert code == 0

    def test_imap(self):
        for site in self.imap_sites:
            code = process_cert(CERT=site)
            assert code == 0

    def test_imaps(self):
        for site in self.imaps_sites:
            code = process_cert(CERT=site)
            assert code == 0
    
    def test_timeout(self):
        test_start = time.time()
        code = process_cert(CERT='0.0.0.1', limit=2)
        test_end = time.time()
        print("code:", code)
        assert code == 1
        assert test_end - test_start >= 1
        