# showcert - simple OpenSSL for humans

micro-cheatsheet (only most often used commands):
~~~
showcert github.com
showcert smtp.google.com:25
showcert --chain -o pem google.com > google-fullchain.pem
sudo showcert -q :le -w50 || echo local LetsEncrypt certificates will expire in less then 50 days
~~~

Showcert tries to follow these principles:
- Simple things must be simple. More complex things may require some options. 
- Be simple and cover 9/10 routine certificate-related tasks.
- If showcert missing some rarely used feature and user needs to use openssl for it - okay.

~~~bash
# You will never forget how to use it:
$ showcert github.com
IP: 140.82.121.3
Names: github.com www.github.com
notBefore: 2022-03-15 00:00:00 (182 days old)
notAfter: 2023-03-15 23:59:59 (183 days left)
Issuer: C=US O=DigiCert Inc CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1

# Compare it against openssl:
# two redirections, pipe, two invokations and 5 unneeded options
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

## STARTTLS implementation
showcert has built-in support for STARTTLS for SMTP (port 25), POP3 (port 110) and IMAP (port 143). You can select proper method with `--starttls` option (or disable it with `--starttls no`), but default value (`auto`) is OK for most cases. This option is needed only if you test servers on non-standard ports.


## Installation
`pipx install showcert`

Or right from repo: `pipx install git+https://github.com/yaroslaff/showcert` 

Or use old way via pip/pip3:
- `pip3 install showcert` (just install)
- `pip3 install -U showcert` (upgrade)
- `pip3 install -U git+https://github.com/yaroslaff/showcert` (install/upgrade from git)

## Exit code
showcert will return non-zero exit code (1) in case of any error (including expired certificate or host mismatch).
If `-w DAYS` used, non-zero (2) will be returned for valid certificates, which will expire in `DAYS` days or sooner.

## Usage

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
