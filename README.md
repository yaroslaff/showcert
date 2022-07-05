# showcert
Simple CLI tool with clean output to show/verify local (.pem) and remote SSL certificates. (For those, who can do this with openssl, but often have to search for right syntax or hate to write grep every time)

~~~
$ showcert github.com
Names: github.com www.github.com
notBefore: 2022-03-15 00:00:00 (108 days old)
notAfter: 2023-03-15 23:59:59 (257 days left)
Issuer: C=US O=DigiCert Inc CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1
~~~

Also:
- `showcert /etc/ssl/certs/ssl-cert-snakeoil.pem` (show certificate from local file)
- `showcert imap.gmail.com:995` (show certificate for gmail IMAP)
- `showcert -i -n google.com localhost` (show certificate for google.com on my local server, even if it's not valid)
- `for cert in /etc/letsencrypt/live/*/cert.pem; do {me} -q -w $cert; done` (Look for expiring LetsEncrypt certificates)


## Limitations
showcert shows only first certificate from PEM file (if there are many) and shows only certificate presented over SSL connection, but can not, for example, verify SMTP STARTTLS certificate (you can verify it locally, but not over network).

## Installation
`pip3 install showcert`

## Exit code
showcert will return non-zero exit code in case of any error (including expired certificate or host mismatch).
If `-w DAYS` used, non-zero will be returned for valid certificates, which will expire in `DAYS` days or sooner.

## Usage

~~~shell
usage: showcert [-h] [-n NAME] [-i] [-q] [-w [DAYS]] CERT

Show local/remote SSL certificate info v0.0.8

positional arguments:
  CERT                  /path/cert.pem or google.com or google.com:443

optional arguments:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  name for SNI (if not same as CERT host)
  -i, --insecure        Do not verify remote certificate
  -q, --quiet           Print only warning/problems
  -w [DAYS], --warn [DAYS]
                        Warn about expiring certificates (def: 20 days)

Examples:  
  # just check remote certificate
  /usr/local/bin/showcert example.com

  # check cert for example.com on new.example.com, do not verify
  /usr/local/bin/showcert new.example.com -n example.com -i

  # dump info from local certificate file
  /usr/local/bin/showcert /etc/letsencrypt/live/example.com/fullchain.pem

  # verify cert quietly and print to stderr only if it will expire in one week
  /usr/local/bin/showcert -q -w 7 github.com
~~~
