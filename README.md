# showcert
Simple CLI tool with clean output to show local (.pem) and remote SSL certificates. (For those, who can do this with openssl, but often have to search for right syntax)

~~~
Names: github.com www.github.com
notBefore: 2022-03-15 00:00:00 (108 days old)
notAfter: 2023-03-15 23:59:59 (257 days left)
Issuer: C=US O=DigiCert Inc CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1
~~~

Also:
- `showcert /etc/ssl/certs/ssl-cert-snakeoil.pem` (show certificate from local file)
- `showcert imap.gmail.com:995` (show certificate for gmail IMAP)
- `showcert -i -n google.com localhost` (show certificate for google.com on my local server, even if it's not valid)


## Limitations
showcert shows only first certificate from PEM file (if there are many) and shows only certificate presented over SSL connection, but can not, for example, verify SMTP STARTTLS certificate (you can verify it locally, but not over network).

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
