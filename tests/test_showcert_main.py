from unittest import mock
from showcert.cli.showcert_main import main

def test_main():
    with mock.patch('sys.argv', ['showcert_main.py', 'github.com']):
                    main()
                    