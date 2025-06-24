import time
from showcert import process_cert
from showcert.exceptions import InvalidAddress
import random
import string
import pytest

class TestShowcertRemote():

    showcert = 'showcert'

    sites = [ 'github.com', 'okerr.com', 'www-security.com', 'gmail.com' ]
    wildcard_sites = [ 'www.badssl.com' ]
    badssl_sites = ['expired.badssl.com', 'wrong.host.badssl.com', 'self-signed.badssl.com', 'untrusted-root.badssl.com']
    pop3_sites = ['pop.yandex.ru:110']
    pop3s_sites = ['pop.yandex.ru:995', 'pop.gmail.com:995']
    imap_sites = ['imap.yandex.ru:143']
    imaps_sites = ['imap.yandex.ru:993', 'imap.gmail.com:993']
    smtp_sites = ['smtp.yandex.ru:25']
    ev_sites = ['www.bankofamerica.com', 'www.hsbc.com.hk']

    def test_https(self):
        for site in self.sites:
            print("test site {}".format(site))
            code = process_cert(CERT=site)
            assert code == 0

    def test_https_chain(self):
        # warn if expires "too soon" in 2000 days
        code = process_cert(CERT=self.sites[0], chain=True)
        assert code == 0
        code = process_cert(CERT=self.sites[0], chain=True, output='full')
        assert code == 0
        code = process_cert(CERT=self.sites[0], chain=True, output='pem')
        assert code == 0
        code = process_cert(CERT=self.sites[0], chain=True, output='names')
        assert code == 0
        code = process_cert(CERT=self.sites[0], chain=True, output='dnames')
        assert code == 0


    def test_https_methods(self):
        code = process_cert(CERT=self.sites[0], starttls='no')
        assert code == 0

        with pytest.raises(ValueError):
            process_cert(CERT=self.sites[0], starttls='nosuchmethod')

    def test_invalid_address(self):
        with pytest.raises(InvalidAddress):
            process_cert("aa:bb.com:443")
        with pytest.raises(InvalidAddress):
            process_cert("github.com:notaport")



    def test_https_warn(self):
        # warn if expires "too soon" in 2000 days
        code = process_cert(CERT=self.sites[0], warn=2000, force_network=True)
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

    def test_ev(self):
        for site in self.ev_sites:
            code = process_cert(CERT=site, insecure=True)
            assert code == 0

    def test_smtp(self):
        for site in self.smtp_sites:
            code = process_cert(CERT=site)
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
        assert code == 1
        assert test_end - test_start >= 1

    def test_nosuchdomain(self):
        name = 'nosuchdomain-' + ''.join(random.choices(string.ascii_lowercase, k=20)) + '.com'
        code = process_cert(CERT=name)
        assert code == 1
