# showcert - simple OpenSSL for humans

![Run tests and upload coverage](https://github.com/yaroslaff/showcert/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/github/yaroslaff/showcert/graph/badge.svg?token=VOACSID3PP)](https://codecov.io/github/yaroslaff/showcert)
[![PyPI version](https://badge.fury.io/py/showcert.svg)](https://badge.fury.io/py/showcert)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/showcert)

showcert consist of two CLI utilities: `showcert` itself - all 'read' operations with X.509 certificates and `gencert` - to create certificates for development purposes.

showcert tries to follow these principles:
- Simple things must be simple. More complex things may require some options. 
- Be simple and cover 9/10 routine certificate-related tasks.
- If showcert missing some rarely used feature and user needs to use openssl for it - okay.


## showcert
micro-cheatsheet (only 5 most often used commands):
~~~bash
# Remote:
showcert github.com
showcert smtp.google.com:25
# save remote certificate or whole --chain
showcert --chain -o pem google.com > google-fullchain.pem

# Local:
# -i for insecure (process self-signed or expired certificates)
showcert -i /etc/ssl/certs/ssl-cert-snakeoil.pem
# letsencrypt-special sugar
sudo showcert -q :le -w50 || echo local LetsEncrypt certificates will expire in less then 50 days
~~~

~~~bash
# You will never forget how to use it:
$ showcert github.com
IP: 140.82.121.3
Names: github.com www.github.com
notBefore: 2022-03-15 00:00:00 (182 days old)
notAfter: 2023-03-15 23:59:59 (183 days left)
Issuer: C=US O=DigiCert Inc CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1

# Compare it against openssl:
# two redirections, pipe, two invocations and 5 unneeded options
$ openssl s_client -connect github.com:443 </dev/null 2>/dev/null | openssl x509 -inform pem -text

# View Google SMTP server cert. starttls mode selected automatically. Same for POP3/IMAP and any simple TLS service
$ showcert smtp.google.com:25

# Save full chain of google.com certificates to local PEM file
$ showcert --chain -o pem google.com > google-fullchain.pem

# Warn about any LetsEncrypt cert which will expire in 50 days or less
# :le is just special token, replaced to /etc/letsencrypt/live/*/fullchain.pem
$ sudo showcert -q :le -w50 || echo panic
/etc/letsencrypt/live/my.example.com/fullchain.pem expires in 47 days
panic
~~~

### STARTTLS implementation
showcert has built-in support for STARTTLS for SMTP (port 25), POP3 (port 110) and IMAP (port 143). You can select proper method with `--starttls` option (or disable it with `--starttls no`), but default value (`auto`) is OK for most cases. This option is needed only if you test servers on non-standard ports.

### Exit code
showcert will return non-zero exit code (1) in case of any error (including expired certificate or host mismatch).
If `-w DAYS` used, non-zero (2) will be returned for valid certificates, which will expire in `DAYS` days or sooner.

### Usage

~~~shell
$ bin/showcert -h
usage: showcert [-h] [-i] [--output OUTPUT] [-c] [-w [DAYS]] [-q] [-n NAME] [-t METHOD] [-l TIME]
                [--ca CA] [--net]
                CERT [CERT ...]

Show local/remote SSL certificate info v0.1.15

positional arguments:
  CERT                  path, - (stdin), ":le" (letsencrypt cert path), hostname or hostname:port

optional arguments:
  -h, --help            show this help message and exit
  -i, --insecure        Do not verify remote certificate
  --output OUTPUT, -o OUTPUT
                        output format: brief, full, names, dnames (for certbot), pem, no.
  -c, --chain           Show chain (not only server certificate)
  -w [DAYS], --warn [DAYS]
                        Warn about expiring certificates (def: 20 days)

Rarely needed options:
  -q, --quiet           Quiet mode, same as --output no
  -n NAME, --name NAME  name for SNI (if not same as CERT host)
  -t METHOD, --starttls METHOD
                        starttls method: auto (default, and OK almost always), no, imap, smtp, pop3
  -l TIME, --limit TIME
                        socket timeout (def: 5)
  --ca CA               path to trusted CA certificates, def: /usr/local/lib/python3.9/dist-packages/certifi/cacert.pem
  --net                 Force network check (if you want to check host and have file/dir with same name in current directory)

Examples:  
  # just check remote certificate
  bin/showcert example.com

  # check SMTP server certificate (autodetected: --starttls smtp )
  bin/showcert smtp.google.com:25

  # save fullchain from google SMTP to local PEM file
  bin/showcert --chain -o pem google.com > google-fullchain.pem
  
  # look for expiring letsencrypt certificates 
  # :le is alias for /etc/letsencrypt/live/*/fullchain.pem 
  bin/showcert :le -q -w 20 || echo "expiring soon!"
~~~

## gencert
Gencert is simple tool to quickly generate X.509 certificates **for development purposes**.
I am not sure if they are very secure. Do not use it in real production!

### Generate self-signed cert
~~~shell
gencert example.com www.example.com
~~~
This will make `example.com.pem` file with both certificate and key in one file. Add `--key example.com.key` to store key in separate file. Add `--cert mycert.pem` to store certificate in different file name.

### Your own CA in two simple commands
Generate CA cert/key:
~~~shell
gencert --ca "My own CA"
~~~
This will make My-own-CA.pem and private key My-own-CA.key (Override with `--cert` and `--key`).

Generate signed certificate:
~~~shell
gencert --cacert My-own-CA.pem example.com
~~~
Done!

`--cacert` is required, `--cakey` is optional (omitted in example), gencert will look for CA private key in following order:
- in`--cakey` PEM file (if given)
- in `--cacert` PEM file (if will be found there). 
- guessed filename. If `--cacert` is CA.pem, gencert will try to load from CA.key.


You may verify certificate with showcert and openssl:
~~~shell
# verify with showcert (unless '-i' given, showcert expects a valid certificate)
$ showcert --ca MyCA.pem example.com.pem
Names: example.com
notBefore: 2024-01-26 11:30:24 (0 days old)
notAfter: 2025-01-25 11:30:24 (364 days left)
Issuer: CN=MyCA

# verify with openssl
$ openssl verify -CAfile MyCA.pem example.com.pem 
example.com.pem: OK
~~~

## Installation
`pipx install showcert`

Or right from repo: `pipx install git+https://github.com/yaroslaff/showcert` 

Or use old way via pip/pip3:
- `pip3 install showcert` (just install)
- `pip3 install -U showcert` (upgrade)
- `pip3 install -U git+https://github.com/yaroslaff/showcert` (install/upgrade from git)
