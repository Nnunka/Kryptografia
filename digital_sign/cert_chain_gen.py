from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime
import os

# Funkcja do generowania pary kluczy RSA
def generate_key_pair():
    """
    Generuje parę kluczy RSA o długości 2048 bitów.

    Returns:
        rsa.RSAPrivateKey: Obiekt klucza prywatnego RSA.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,  # Typowy wykładnik publiczny RSA
        key_size=2048,  # Rozmiar klucza w bitach
    )
    return key

# Funkcja do tworzenia certyfikatu
def create_certificate(subject_name, issuer_name, issuer_key, public_key, is_ca=False):
    """
    Tworzy certyfikat X.509.

    Args:
        subject_name (x509.Name): Nazwa podmiotu certyfikatu.
        issuer_name (x509.Name): Nazwa wystawcy certyfikatu.
        issuer_key (rsa.RSAPrivateKey): Klucz prywatny wystawcy.
        public_key (rsa.RSAPublicKey): Klucz publiczny dołączany do certyfikatu.
        is_ca (bool): Czy certyfikat powinien być certyfikatem CA.

    Returns:
        x509.Certificate: Wygenerowany certyfikat X.509.
    """
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)  # Ustawia nazwę podmiotu
    builder = builder.issuer_name(issuer_name)  # Ustawia nazwę wystawcy
    builder = builder.public_key(public_key)  # Dołącza klucz publiczny
    builder = builder.serial_number(x509.random_serial_number())  # Generuje losowy numer seryjny

    # Ustawia okres ważności certyfikatu
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))

    # Dodaje rozszerzenie BasicConstraints (określające, czy certyfikat jest CA)
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )

    # Podpisanie certyfikatu kluczem prywatnym wystawcy
    certificate = builder.sign(
        private_key=issuer_key, algorithm=hashes.SHA256()
    )
    return certificate

# Funkcja do zapisywania certyfikatu w pliku PEM
def save_certificate(cert, filename):
    """
    Zapisuje certyfikat X.509 w formacie PEM do pliku.

    Args:
        cert (x509.Certificate): Certyfikat do zapisania.
        filename (str): Ścieżka do pliku, w którym zostanie zapisany certyfikat.
    """
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# Funkcja do zapisywania klucza prywatnego w pliku PEM
def save_private_key(key, filename):
    """
    Zapisuje klucz prywatny w formacie PEM do pliku.

    Args:
        key (rsa.RSAPrivateKey): Klucz prywatny do zapisania.
        filename (str): Ścieżka do pliku, w którym zostanie zapisany klucz.
    """
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,  # Format kodowania PEM
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # Tradycyjny format OpenSSL
            encryption_algorithm=serialization.NoEncryption()  # Brak szyfrowania klucza
        ))

# Funkcja do symulacji łańcucha certyfikatów
def simulate_certificate_chain():
    """
    Generuje łańcuch certyfikatów, w tym Root CA, Intermediate CA i End Entity.
    Certyfikaty i klucze są zapisywane w folderze `cert_chain`.
    """
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
        issuer_name=root_subject,  # Root CA jest swoim własnym wystawcą
        issuer_key=root_key,
        public_key=root_key.public_key(),
        is_ca=True  # Certyfikat CA
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
        issuer_name=root_cert.subject,  # Root CA wystawia certyfikat Intermediate CA
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        is_ca=True  # Certyfikat CA
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
        issuer_name=intermediate_cert.subject,  # Intermediate CA wystawia certyfikat End Entity
        issuer_key=intermediate_key,
        public_key=end_entity_key.public_key(),
        is_ca=False  # Nie jest certyfikatem CA
    )
    save_certificate(end_entity_cert, os.path.join(folder, "end_entity_cert.pem"))
    save_private_key(end_entity_key, os.path.join(folder, "end_entity_key.pem"))

# Główna funkcja programu
if __name__ == "__main__":
    """
    Główna funkcja programu.
    Symuluje łańcuch certyfikatów i zapisuje certyfikaty oraz klucze w folderze `cert_chain`.
    """
    simulate_certificate_chain()
