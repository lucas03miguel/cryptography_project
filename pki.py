from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime


def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    print("Public key: ", public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    return private_key, public_key


def create_root_ca():
    private_key, public_key = generate_key_pair()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
    ])

    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)\
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc))\
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(private_key, hashes.SHA256())
    
    return private_key, certificate


def create_intermediate_ca(root_private_key, root_cert):
    private_key, public_key = generate_key_pair()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lucas e Joao"),
        x509.NameAttribute(NameOID.COMMON_NAME, "criptografia"),
    ])
    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(root_cert.subject).public_key(public_key)\
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc))\
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(root_private_key, hashes.SHA256())
    
    return private_key, certificate


def issue_certificate(intermediate_private_key, intermediate_cert, common_name):
    private_key, public_key = generate_key_pair()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "User"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(intermediate_cert.subject).public_key(public_key)\
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc))\
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))\
        .sign(intermediate_private_key, hashes.SHA256())
    
    return private_key, certificate


class CertificateRevocationList:
    def __init__(self):
        self.revoked_serial_numbers = set()

    def revoke_certificate(self, cert):
        self.revoked_serial_numbers.add(cert.serial_number)
        print(f"\nCertificate with serial number {cert.serial_number} has been revoked.\n")

    def is_revoked(self, cert):
        return cert.serial_number in self.revoked_serial_numbers


def main():
    root_private_key, root_cert = create_root_ca()
    intermediate_private_key, intermediate_cert = create_intermediate_ca(root_private_key, root_cert)
    user_private_key, user_cert = issue_certificate(intermediate_private_key, intermediate_cert, "User1")


    crl = CertificateRevocationList()
    print("Is the user's certificate revoked?", crl.is_revoked(user_cert))

    crl.revoke_certificate(user_cert)

    print("Is the user's certificate revoked?", crl.is_revoked(user_cert))

    
if __name__ == "__main__":
    main()

