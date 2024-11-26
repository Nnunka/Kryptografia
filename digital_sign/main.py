import sys
import os
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QApplication
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from PyPDF2 import PdfReader
from MainWindow import Ui_MainWindow

def ensure_data_folder():
    if not os.path.exists("data"):
        os.makedirs("data")

class DigitalSignatureApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Connect buttons to methods
        self.ui.select_file.clicked.connect(self.select_file)
        self.ui.generate_keys.clicked.connect(self.generate_keys)
        self.ui.sing_file.clicked.connect(self.sign_file)
        self.ui.verify_signature.clicked.connect(self.verify_signature)
        self.ui.load_certificate.clicked.connect(self.load_certificate)
        self.ui.load_chain.clicked.connect(self.load_certificate_chain)

        # RSA Keys
        self.private_key = None
        self.public_key = None

        # Selected file
        self.selected_file = None

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Wybierz plik PDF", "", "PDF Files (*.pdf)")
        if file_path:
            self.selected_file = file_path
            self.ui.label.setText(f"Wybrano plik: {os.path.basename(file_path)}")
        else:
            self.ui.label.setText("Nie wybrano pliku")

    def generate_keys(self):
        ensure_data_folder()  # Ensure the "data" folder exists
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

        # Save keys to files
        private_key_path = os.path.join("data", "private_key.pem")
        public_key_path = os.path.join("data", "public_key.pem")

        with open(private_key_path, "wb") as priv_file:
            priv_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        with open(public_key_path, "wb") as pub_file:
            pub_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        self.ui.label_2.setText(f"Klucze zapisane w folderze 'data' jako {os.path.basename(private_key_path)} i {os.path.basename(public_key_path)}.")


    def sign_file(self):
        if not self.selected_file:
            self.ui.label_2.setText("Nie wybrano pliku PDF.")
            return

        if not self.private_key:
            self.ui.label_2.setText("Najpierw wygeneruj klucze RSA.")
            return

        ensure_data_folder()  # Ensure the "data" folder exists

        # Calculate hash
        document_hash = self.calculate_pdf_hash(self.selected_file)

        # Sign the hash
        signature = self.private_key.sign(
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Save the signature
        signature_path = os.path.join("data", "signature.sig")
        with open(signature_path, "wb") as sig_file:
            sig_file.write(signature)

        self.ui.label_2.setText(f"Plik podpisany i zapisany w folderze 'data' jako {os.path.basename(signature_path)}.")

    def verify_signature(self):
        if not self.selected_file:
            self.ui.label_2.setText("Nie wybrano pliku PDF.")
            return

        signature_path = os.path.join("data", "signature.sig")
        if not os.path.exists(signature_path):
            self.ui.label_2.setText("Brak podpisu w folderze 'data'.")
            return

        if not self.public_key:
            self.ui.label_2.setText("Brak klucza publicznego do weryfikacji.")
            return

        # Calculate hash
        document_hash = self.calculate_pdf_hash(self.selected_file)

        # Read the signature
        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()

        # Verify the signature
        try:
            self.public_key.verify(
                signature,
                document_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.ui.label_2.setText("Podpis jest poprawny.")
        except Exception as e:
            self.ui.label_2.setText("Weryfikacja podpisu nie powiodła się.")


    def calculate_pdf_hash(self, pdf_path):
        reader = PdfReader(pdf_path)
        pdf_content = b"".join(page.extract_text().encode() for page in reader.pages)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pdf_content)
        return digest.finalize()

    def load_certificate(self):
        file_dialog = QFileDialog()
        cert_path, _ = file_dialog.getOpenFileName(self, "Wybierz certyfikat", "", "Certyfikaty (*.pem *.crt *.der)")
        if not cert_path:
            return

        try:
            with open(cert_path, "rb") as cert_file:
                cert_data = cert_file.read()
                if cert_path.endswith(".pem"):
                    certificate = load_pem_x509_certificate(cert_data)
                elif cert_path.endswith(".der"):
                    certificate = load_der_x509_certificate(cert_data)
                else:
                    self.ui.certificate_info.setText("Nieobsługiwany format pliku.")
                    return

                self.display_certificate_info(certificate)
        except Exception as e:
            self.ui.certificate_info.setText(f"Błąd podczas wczytywania certyfikatu: {str(e)}")

    def display_certificate_info(self, certificate):
        info = []

        info.append(f"Wersja: {certificate.version.name}")
        info.append(f"Wystawca: {certificate.issuer.rfc4514_string()}")
        info.append(f"Odbiorca: {certificate.subject.rfc4514_string()}")
        info.append(f"Algorytm klucza publicznego: {certificate.signature_algorithm_oid._name}")
        info.append(f"Data ważności od: {certificate.not_valid_before_utc}")
        info.append(f"Data ważności do: {certificate.not_valid_after_utc}")

        info.append("Rozszerzenia:")
        for extension in certificate.extensions:
            info.append(f"  - {extension.oid._name}: {extension.value}")

        self.ui.certificate_info.setText("\n".join(info))

    def load_certificate_chain(self):
        """
        Wczytuje i wyświetla informacje o łańcuchu certyfikatów.
        """
        cert_folder = "cert_chain"
        if not os.path.exists(cert_folder):
            self.ui.certificate_info.setText("Folder 'cert_chain' nie istnieje.")
            return

        cert_files = ["root_cert.pem", "intermediate_cert.pem", "end_entity_cert.pem"]
        chain_info = []

        for cert_file in cert_files:
            cert_path = os.path.join(cert_folder, cert_file)
            if not os.path.exists(cert_path):
                chain_info.append(f"{cert_file}: Nie znaleziono pliku.")
                continue

            try:
                with open(cert_path, "rb") as f:
                    cert_data = f.read()
                    certificate = load_pem_x509_certificate(cert_data)

                    chain_info.append(f"Certyfikat: {cert_file}")
                    chain_info.append(f"  Wersja: {certificate.version.name}")
                    chain_info.append(f"  Wystawca: {certificate.issuer.rfc4514_string()}")
                    chain_info.append(f"  Odbiorca: {certificate.subject.rfc4514_string()}")
                    chain_info.append(f"  Algorytm podpisu: {certificate.signature_algorithm_oid._name}")
                    chain_info.append(f"  Data ważności od: {certificate.not_valid_before_utc}")
                    chain_info.append(f"  Data ważności do: {certificate.not_valid_after_utc}")
                    chain_info.append("")
            except Exception as e:
                chain_info.append(f"{cert_file}: Błąd wczytywania - {str(e)}")

        self.ui.certificate_info.setText("\n".join(chain_info))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DigitalSignatureApp()
    window.show()
    sys.exit(app.exec())
