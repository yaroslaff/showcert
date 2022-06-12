# showcert
Simple CLI tool to check local (.pem) and remote SSL certificates with clean output.

~~~
$ showcert github.com
Names: github.com www.github.com
notBefore: 2022-03-15 00:00:00
notAfter: 2023-03-15 23:59:59
Issuer: C=US O=DigiCert Inc CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1

~~~

## Installation
`pip3 install showcert`

## Usage

~~~shell
usage: showcert [-h] [-n NAME] [-i] CERT

Show local/remote SSL certificate info

positional arguments:
  CERT                  /path/cert.pem or google.com or google.com:443

optional arguments:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  name for SNI (if not same as CERT host)
  -i, --insecure        Do not verify remote certificate

Examples:  
  # just check remote certificate
  bin/showcert example.com

  # check cert for example.com on new.example.com, do not verify
  bin/showcert new.example.com -n example.com -i

  # dump info from local certificate file
  bin/showcert /etc/letsencrypt/live/example.com/fullchain.pem
~~~
