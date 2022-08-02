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
- `showcert pop.yandex.ru:110` (show cert for yandex POP3, yes, it will do STARTTLS automatically)
- `showcert -i -n google.com localhost` (show certificate for google.com on my local server, even if it's not valid)
- `showcert *.pem -q -w` - quietly check all *.pem files in current directory, and warn if any expires soon
- `showcert :le` - same as `showcert /etc/letsencrypt/live/*/cert.pem`


## STARTTLS implementation
showcert has built-in support for STARTTLS for SMTP (port 25), POP3 (port 110) and IMAP (port 143). You can select proper method with `--starttls` option (or disable it with `--starttls no`), but default value ('auto') is OK for most cases. This option is needed only if you test servers on non-standard ports.

## Limitations
showcert shows only first certificate from PEM file (if there are many)

## Installation
`pip3 install showcert`

## Exit code
showcert will return non-zero exit code in case of any error (including expired certificate or host mismatch).
If `-w DAYS` used, non-zero will be returned for valid certificates, which will expire in `DAYS` days or sooner.

## Usage

~~~shell
usage: showcert [-h] [-n NAME] [-i] [-q] [-w [DAYS]] [-t METHOD] CERT [CERT ...]

Show local/remote SSL certificate info v0.0.14

positional arguments:
  CERT                  /path/cert.pem or glob pattern or :le google.com or google.com:443

optional arguments:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  name for SNI (if not same as CERT host)
  -i, --insecure        Do not verify remote certificate
  -q, --quiet           Print only warning/problems
  -w [DAYS], --warn [DAYS]
                        Warn about expiring certificates (def: 20 days)
  -t METHOD, --starttls METHOD
                        starttls method: auto (default, and OK almost always), no, imap, smtp, pop3

Examples:  
  # just check remote certificate
  /usr/local/bin/showcert example.com

  # check cert for example.com on new.example.com, do not verify
  /usr/local/bin/showcert new.example.com -n example.com -i

  # dump info from local certificate file(s)
  /usr/local/bin/showcert *.pem

  # look for expiring letsencrypt certificates (:le is alias for /etc/letsencrypt/live/*/cert.pem)
  /usr/local/bin/showcert :le -q -w
~~~
