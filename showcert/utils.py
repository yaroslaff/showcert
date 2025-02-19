from OpenSSL.crypto import X509
from cryptography import x509
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
from cryptography.hazmat.backends import default_backend


def convert_openssl_to_cryptography(openssl_cert: X509) -> x509.Certificate:
    # Convert OpenSSL.crypto.X509 to PEM format
    pem_data = dump_certificate(FILETYPE_PEM, openssl_cert)

    # Load PEM data into cryptography.x509.Certificate
    certificate = x509.load_pem_x509_certificate(pem_data, default_backend())

    return certificate
