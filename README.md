# showcert
Simple tool to check local (.pem) and remote SSL certificates. Shows

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

## Example output
~~~
$ bin/showcert cloudflare.com
Names: cloudflare.com *.staging.cloudflare.com *.cloudflare.com *.amp.cloudflare.com *.dns.cloudflare.com
notBefore: 2022-05-04 00:00:00
notAfter: 2023-05-04 23:59:59
Issuer: C=US O=Cloudflare, Inc. CN=Cloudflare Inc ECC CA-3
~~~