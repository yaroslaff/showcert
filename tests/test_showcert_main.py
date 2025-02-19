from unittest import mock
from showcert.cli.showcert_main import main


snakeoil = '/etc/ssl/certs/ssl-cert-snakeoil.pem'

def test_main():
    with mock.patch('sys.argv', ['showcert_main.py', 'github.com']):
                    code = main()
                    assert code == 0
                    
def test_main_le():
    with mock.patch('sys.argv', ['showcert_main.py', ':le']):
                    code = main()
                    assert code == 0

def test_main_snakeoil():
    with mock.patch('sys.argv', ['showcert_main.py', snakeoil]):
                    code = main()
                    assert code == 1

def test_main_notacert():
    with mock.patch('sys.argv', ['showcert_main.py', "/etc/fstab"]):
                    code = main()
                    assert code == 1
