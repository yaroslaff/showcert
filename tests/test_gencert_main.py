from unittest import mock
from showcert.cli.gencert_main import main
import os
def test_cacert():
    with mock.patch('sys.argv', ['gencert_main.py', 
        '--ca', '--cert', '/tmp/ca.pem', '--key', '/tmp/ca-priv.pem', "My CA"]):                    
                    code = main()
                    assert code == 0


def test_cacert_combined():
    with mock.patch('sys.argv', ['gencert_main.py', 
        '--ca', '--cert', '/tmp/ca2.pem', "My CA"]):                    
                    code = main()
                    assert code == 0


def test_cert():
    with mock.patch('sys.argv', ['gencert_main.py', 
        '--cacert', '/tmp/ca.pem', '--cakey', '/tmp/ca-priv.pem', 'example.com', 'www.example.com', '0.0.0.1']):
                    code = main()
                    assert code == 0
                    os.unlink('example.com.pem')

def test_cert_combined():
    with mock.patch('sys.argv', ['gencert_main.py', 
        '--cacert', '/tmp/ca2.pem', 'example.com', 'www.example.com']):
                    code = main()
                    assert code == 0
                    os.unlink('example.com.pem')
