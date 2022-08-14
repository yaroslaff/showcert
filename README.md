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
- `showcert pop.gmail.com:995` (show certificate for gmail POP3 over SSL)
- `showcert pop.yandex.ru:110` (show cert for yandex POP3. Yes, it will do STARTTLS automatically)
- `showcert -i -n google.com localhost` (show certificate for google.com on my local server, even if it's not valid)
- `showcert *.pem -w` - check all *.pem files in current directory, and warn if any expires soon. Add `-o no` for quiet mode
- `showcert /etc/ssl/certs/ssl-cert-snakeoil.pem` (show certificate from local file, or from stdin if path is `-`)
- `showcert google.com --chain -o pem > fullchain.pem` - 'steal' remote server fullchain.pem (without privkey, obviously)

LetsEncrypt specific features:
- `showcert -w 30 :le` - same as `showcert -w 30 /etc/letsencrypt/live/*/fullchain.pem`. Warn
- ``certbot certonly --webroot PATH `showcert -o dnames example.com``` - generate LetsEncrypt certificate, using showcert to obtain list if domain names like `-d example.com -d www.example.com`.


## STARTTLS implementation
showcert has built-in support for STARTTLS for SMTP (port 25), POP3 (port 110) and IMAP (port 143). You can select proper method with `--starttls` option (or disable it with `--starttls no`), but default value (`auto`) is OK for most cases. This option is needed only if you test servers on non-standard ports.


## Installation
`pip3 install showcert`

## Exit code
showcert will return non-zero exit code (1) in case of any error (including expired certificate or host mismatch).
If `-w DAYS` used, non-zero (2) will be returned for valid certificates, which will expire in `DAYS` days or sooner.

## Usage

~~~shell
usage: showcert [-h] [-i] [--output OUTPUT] [-c] [-w [DAYS]] [-n NAME] [-t METHOD] [--ca CA] CERT [CERT ...]

Show local/remote SSL certificate info v0.1.3

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
  -n NAME, --name NAME  name for SNI (if not same as CERT host)
  -t METHOD, --starttls METHOD
                        starttls method: auto (default, and OK almost always), no, imap, smtp, pop3
  --ca CA               path to trusted CA certificates, def: /home/xenon/.local/lib/python3.9/site-packages/certifi/cacert.pem

~~~
