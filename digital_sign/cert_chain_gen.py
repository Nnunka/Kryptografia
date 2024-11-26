from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime
import os

# Funkcja do generowania pary kluczy RSA
def generate_key_pair():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return key

# Funkcja do tworzenia certyfikatu
def create_certificate(subject_name, issuer_name, issuer_key, public_key, is_ca=False):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    
    # Użycie datetime.datetime.now() z UTC zamiast utcnow()
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )

    certificate = builder.sign(
        private_key=issuer_key, algorithm=hashes.SHA256()
    )
    return certificate

# Funkcja do zapisywania certyfikatu w pliku PEM
def save_certificate(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# Funkcja do zapisywania klucza prywatnego w pliku PEM
def save_private_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

# Funkcja do symulacji łańcucha certyfikatów
def simulate_certificate_chain():
    # Upewnij się, że folder 'cert_chain' istnieje
    folder = "cert_chain"
    os.makedirs(folder, exist_ok=True)

    # Tworzenie certyfikatu Root CA
    root_key = generate_key_pair()
    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
    ])
    root_cert = create_certificate(
        subject_name=root_subject,
        issuer_name=root_subject, 
        issuer_key=root_key,
        public_key=root_key.public_key(),
        is_ca=True
    )
    save_certificate(root_cert, os.path.join(folder, "root_cert.pem"))
    save_private_key(root_key, os.path.join(folder, "root_key.pem"))

    # Tworzenie certyfikatu Intermediate CA
    intermediate_key = generate_key_pair()
    intermediate_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intermediate CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA"),
    ])
    intermediate_cert = create_certificate(
        subject_name=intermediate_subject,
        issuer_name=root_cert.subject, 
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        is_ca=True
    )
    save_certificate(intermediate_cert, os.path.join(folder, "intermediate_cert.pem"))
    save_private_key(intermediate_key, os.path.join(folder, "intermediate_key.pem"))

    # Tworzenie certyfikatu End Entity
    end_entity_key = generate_key_pair()
    end_entity_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "End Entity"),
        x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com"),
    ])
    end_entity_cert = create_certificate(
        subject_name=end_entity_subject,
        issuer_name=intermediate_cert.subject,  
        issuer_key=intermediate_key,
        public_key=end_entity_key.public_key(),
        is_ca=False
    )
    save_certificate(end_entity_cert, os.path.join(folder, "end_entity_cert.pem"))
    save_private_key(end_entity_key, os.path.join(folder, "end_entity_key.pem"))

    print(f"Certyfikaty zostały wygenerowane i zapisane w folderze '{folder}':")
    print("  - Root CA: root_cert.pem")
    print("  - Intermediate CA: intermediate_cert.pem")
    print("  - End Entity: end_entity_cert.pem")

# Główna funkcja programu
if __name__ == "__main__":
    simulate_certificate_chain()
