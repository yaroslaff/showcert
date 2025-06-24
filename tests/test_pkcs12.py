from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from showcert import process_cert
import datetime
from unittest import mock
import os

class TestShowcertPKCS12():

    showcert = 'showcert'
    gencert = 'gencert'
    testcert_p12 = '/tmp/testcert.p12'
    testchain_p12 = '/tmp/testchain.p12'    
    password = 'mysecret'


    def make_p12chain(self):
        # Generate root CA
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
        ])
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256())
        )

        # Generate intermediate CA
        int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        int_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intermediate CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA"),
        ])
        int_cert = (
            x509.CertificateBuilder()
            .subject_name(int_name)
            .issuer_name(root_name)
            .public_key(int_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=730))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, hashes.SHA256())
        )

        # Generate end-entity certificate
        ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ee_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
        ])
        ee_cert = (
            x509.CertificateBuilder()
            .subject_name(ee_name)
            .issuer_name(int_name)
            .public_key(ee_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(int_key, hashes.SHA256())
        )

        # Create PKCS12 with chain (end-entity cert + intermediate + root)
        p12_data = pkcs12.serialize_key_and_certificates(
            name=b"cert-with-chain",
            key=ee_key,
            cert=ee_cert,
            cas=[int_cert, root_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(self.password.encode())
        )

        with open(self.testchain_p12, "wb") as f:
            f.write(p12_data)

        print(f"Generated certificate with chain: {self.testchain_p12}")
        

    def make_p12(self):
        # Generate private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create self-signed cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256())

        # Export as PKCS12 (.p12)
        password = self.password.encode()  # Change this!
        p12 = serialization.pkcs12.serialize_key_and_certificates(
            name=b"self-signed-cert",
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(self.password.encode())
        )

        with open(self.testcert_p12, "wb") as f:
            f.write(p12)

        print("Generated self_signed.p12")


    def test_p12(self):

        self.make_p12()

        rc = process_cert(CERT=self.testcert_p12, password=self.password)
        assert(rc == 1)

        rc = process_cert(CERT=self.testcert_p12, password=self.password, insecure=True)
        assert(rc == 0)

        # os.unlink(self.testcert_p12)

    def test_chain_p12(self):

        self.make_p12chain()

        rc = process_cert(CERT=self.testchain_p12, password=self.password, insecure=True)
        assert(rc == 0)

        # os.unlink(self.testcert_p12)
