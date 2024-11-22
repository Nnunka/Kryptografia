import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QFileDialog, QLabel, QTextEdit
)
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from PyPDF2 import PdfReader

class DigitalSignatureApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Podpis Cyfrowy PDF i Certyfikaty X.509")
        self.setGeometry(200, 200, 800, 600)

        self.initUI()

        # Klucze RSA
        self.private_key = None
        self.public_key = None

        # Wybrany plik
        self.selected_file = None

    def initUI(self):
        layout = QVBoxLayout()

        # Etykieta
        self.file_label = QLabel("Nie wybrano pliku")
        self.file_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.file_label)

        # Przycisk wyboru pliku
        select_button = QPushButton("Wybierz plik PDF")
        select_button.clicked.connect(self.select_file)
        layout.addWidget(select_button)

        # Przycisk generowania kluczy
        keygen_button = QPushButton("Wygeneruj klucze RSA")
        keygen_button.clicked.connect(self.generate_keys)
        layout.addWidget(keygen_button)

        # Przycisk podpisania pliku
        sign_button = QPushButton("Podpisz plik PDF")
        sign_button.clicked.connect(self.sign_file)
        layout.addWidget(sign_button)

        # Przycisk weryfikacji podpisu
        verify_button = QPushButton("Zweryfikuj podpis")
        verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(verify_button)

        # Przycisk załadowania certyfikatu
        cert_button = QPushButton("Przeglądaj certyfikat X.509")
        cert_button.clicked.connect(self.load_certificate)
        layout.addWidget(cert_button)

    

        # Etykieta statusu
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # Ustawienie layoutu
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Wybierz plik PDF", "", "PDF Files (*.pdf)")
        if file_path:
            self.selected_file = file_path
            self.file_label.setText(f"Wybrano plik: {os.path.basename(file_path)}")
        else:
            self.file_label.setText("Nie wybrano pliku")

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        self.status_label.setText("Klucze RSA wygenerowane.")

        # Zapis kluczy do plików
        with open("private_key.pem", "wb") as priv_file:
            priv_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        with open("public_key.pem", "wb") as pub_file:
            pub_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        self.status_label.setText("Klucze zapisane jako private_key.pem i public_key.pem.")

    def sign_file(self):
        if not self.selected_file:
            self.status_label.setText("Nie wybrano pliku PDF.")
            return

        if not self.private_key:
            self.status_label.setText("Najpierw wygeneruj klucze RSA.")
            return

        # Obliczanie skrótu
        document_hash = self.calculate_pdf_hash(self.selected_file)
        # Podpisywanie skrótu
        signature = self.private_key.sign(
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Zapisanie podpisu
        with open("signature.sig", "wb") as sig_file:
            sig_file.write(signature)

        self.status_label.setText("Plik podpisany i zapisany jako signature.sig.")

    def verify_signature(self):
        if not self.selected_file:
            self.status_label.setText("Nie wybrano pliku PDF.")
            return

        if not os.path.exists("signature.sig"):
            self.status_label.setText("Brak podpisu (signature.sig).")
            return

        if not self.public_key:
            self.status_label.setText("Brak klucza publicznego do weryfikacji.")
            return

        # Obliczanie skrótu
        document_hash = self.calculate_pdf_hash(self.selected_file)

        # Odczytanie podpisu
        with open("signature.sig", "rb") as sig_file:
            signature = sig_file.read()

        # Weryfikacja
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
            self.status_label.setText("Podpis jest poprawny.")
        except Exception as e:
            self.status_label.setText("Weryfikacja podpisu nie powiodła się.")

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
                    self.certificate_info.setText("Nieobsługiwany format pliku.")
                    return

                self.display_certificate_info(certificate)
        except Exception as e:
            self.certificate_info.setText(f"Błąd podczas wczytywania certyfikatu: {str(e)}")

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

        self.certificate_info.setText("\n".join(info))



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DigitalSignatureApp()
    window.show()
    sys.exit(app.exec())
