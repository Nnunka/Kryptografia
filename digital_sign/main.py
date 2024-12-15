import os
import sys
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QApplication
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from PyPDF2 import PdfReader
from cert_chain_gen import simulate_certificate_chain, ensure_cert_chain_folder
from hmac_utils import generate_hmac_key, load_hmac_key, calculate_hmac, verify_hmac
from MainWindow import Ui_MainWindow
    
def resource_path(relative_path):
    """
    Zwraca ścieżkę do zasobów, zarówno podczas uruchamiania w środowisku deweloperskim, jak i w środowisku PyInstaller.
    """
    try:
        # Gdy aplikacja jest zapakowana w .exe
        base_path = sys._MEIPASS
    except AttributeError:
        # Podczas uruchamiania w środowisku deweloperskim
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def ensure_data_folder():
    """
    Tworzy folder 'data' w katalogu bieżącym aplikacji, jeśli jeszcze nie istnieje.
    """
    data_folder = os.path.abspath("data")  # Tworzenie ścieżki bezpośrednio do folderu 'data'
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)
    return data_folder


class DigitalSignatureApp(QMainWindow):
    """
    Aplikacja PyQt5 do obsługi podpisów cyfrowych PDF oraz weryfikacji certyfikatów.
    """

    def __init__(self):
        """
        Inicjalizuje główne okno aplikacji i podłącza przyciski GUI do odpowiednich funkcji.
        """
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Podłączenie przycisków do metod
        self.ui.select_file.clicked.connect(self.select_file)
        self.ui.generate_keys.clicked.connect(self.generate_keys)
        self.ui.sing_file.clicked.connect(self.sign_file)
        self.ui.verify_signature.clicked.connect(self.verify_signature)
        self.ui.load_certificate.clicked.connect(self.load_certificate)
        self.ui.load_chain.clicked.connect(self.load_certificate_chain)
        self.ui.generate_hmac.clicked.connect(self.generate_hmac)
        self.ui.verify_hmac.clicked.connect(self.verify_hmac)
        self.ui.gen_chain.clicked.connect(self.generate_certificate_chain)



        # Klucze RSA
        self.private_key = None
        self.public_key = None

        # Wybrany plik PDF
        self.selected_file = None


    def select_file(self):
        """
        Umożliwia użytkownikowi wybór pliku PDF do podpisania lub weryfikacji.
        """
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Wybierz plik PDF", "", "PDF Files (*.pdf)")
        if file_path:
            self.selected_file = file_path
            self.ui.label.setText(f"Wybrano plik: {os.path.basename(file_path)}")
        else:
            self.ui.label.setText("Nie wybrano pliku")


#####PODPIS CYFROWY#####
    def generate_keys(self):
        """
        Generuje parę kluczy RSA (prywatny i publiczny), zapisuje je w folderze 'data'
        i wyświetla szczegółowe informacje.
        """
        ensure_data_folder()  # Upewnia się, że folder 'data' istnieje

        # Generowanie klucza prywatnego
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

        # Zapisywanie kluczy do plików
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

        # Wyświetlanie szczegółowych informacji o kluczach
        self.ui.certificate_info.setText(
            "Klucze RSA zostały wygenerowane i zapisane.\n"
            f"Szczegóły:\n"
            f"  - Klucz prywatny zapisany w: {private_key_path}\n"
            f"  - Klucz publiczny zapisany w: {public_key_path}\n\n"
            f"Klucz publiczny (PEM):\n{self.public_key.public_bytes(Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}\n"
        )


    def sign_file(self):
        """
        Podpisuje wybrany plik PDF przy użyciu klucza prywatnego RSA i wyświetla szczegółowe informacje o podpisie.
        Zapisuje podpis w folderze 'data'.
        """
        if not self.selected_file:
            self.ui.label_2.setText("Nie wybrano pliku PDF.")
            return

        if not self.private_key:
            self.ui.label_2.setText("Najpierw wygeneruj klucze RSA.")
            return

        ensure_data_folder()  # Upewnia się, że folder 'data' istnieje

        try:
            # Obliczanie skrótu dokumentu
            document_hash = self.calculate_pdf_hash(self.selected_file)

            # Podpisywanie hasha kluczem prywatnym
            signature = self.private_key.sign(
                document_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Zapis podpisu do pliku
            signature_path = os.path.join("data", "signature.sig")
            with open(signature_path, "wb") as sig_file:
                sig_file.write(signature)

            # Wyświetlenie szczegółowych informacji o podpisie
            self.ui.certificate_info.setText(
                "Plik został podpisany cyfrowo.\n"
                f"Szczegóły podpisu:\n"
                f"  - Algorytm skrótu: SHA256\n"
                f"  - Plik: {os.path.basename(self.selected_file)}\n"
                f"  - Lokalizacja pliku: {self.selected_file}\n"
                f"  - Podpis cyfrowy (HEX): {signature.hex()}\n\n"
                f"Klucz publiczny użyty do weryfikacji:\n"
                f"{self.public_key.public_bytes(Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}"
            )

            self.ui.label_2.setText(f"Plik podpisany i zapisany w folderze 'data' jako {os.path.basename(signature_path)}.")

        except Exception as e:
            self.ui.label_2.setText(f"Błąd podczas podpisywania pliku: {str(e)}")


    def verify_signature(self):
        """
        Weryfikuje podpis cyfrowy dla wybranego pliku PDF i wyświetla szczegółowe informacje.
        """
        if not self.selected_file:
            self.ui.label_2.setText("Nie wybrano pliku PDF.")
            return

        # Ścieżka do pliku z podpisem
        signature_path = os.path.join("data", "signature.sig")

        # Sprawdzenie, czy plik podpisu istnieje
        if not os.path.exists(signature_path):
            self.ui.label_2.setText(f"Brak pliku z podpisem w: {signature_path}. Wygeneruj podpis cyfrowy.")
            return

        try:
            # Odczytanie podpisu
            with open(signature_path, "rb") as sig_file:
                signature = sig_file.read()

            # Oblicz skrót z wybranego pliku PDF
            document_hash = self.calculate_pdf_hash(self.selected_file)

            # Próba weryfikacji podpisu
            self.public_key.verify(
                signature,
                document_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Wyświetlenie szczegółów, jeśli podpis jest poprawny
            self.ui.certificate_info.setText(
                "Weryfikacja podpisu zakończona pomyślnie.\n"
                "Szczegóły weryfikacji:\n"
                f"  - Algorytm skrótu: SHA256\n"
                f"  - Plik: {os.path.basename(self.selected_file)}\n"
                f"  - Lokalizacja pliku: {self.selected_file}\n"
                f"  - Podpis cyfrowy (HEX): {signature.hex()}\n"
                f"  - Klucz publiczny:\n{self.public_key.public_bytes(Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}"
            )

        except Exception as e:
            # Wyświetlenie szczegółów błędu, jeśli weryfikacja się nie powiodła
            self.ui.certificate_info.setText(
                "Weryfikacja podpisu nie powiodła się.\n"
                f"  - Błąd: {str(e)}\n"
                f"  - Plik: {os.path.basename(self.selected_file)}\n"
                f"  - Lokalizacja pliku: {self.selected_file}\n"
            )

    def calculate_pdf_hash(self, pdf_path):
        """
        Oblicza hash (SHA-256) zawartości pliku PDF.

        Args:
            pdf_path (str): Ścieżka do pliku PDF.

        Returns:
            bytes: Hash zawartości PDF.
        """
        reader = PdfReader(pdf_path)
        pdf_content = b"".join(page.extract_text().encode() for page in reader.pages)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pdf_content)
        return digest.finalize()

    def load_certificate(self):
        """
        Wczytuje certyfikat w formacie PEM lub DER i wyświetla jego szczegóły.
        """
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
        """
        Wyświetla szczegóły certyfikatu X.509 w interfejsie graficznym.

        Args:
            certificate (x509.Certificate): Obiekt certyfikatu.
        """
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

#####ŁAŃCUCH CERTYFIKATÓW#####
    def generate_certificate_chain(self):
        """
        Generuje łańcuch certyfikatów (Root CA, Intermediate CA, End Entity)
        i wyświetla informacje o zapisanych plikach.
        """
        try:
            # Generowanie łańcucha certyfikatów
            simulate_certificate_chain()

            # Informacja o sukcesie
            self.ui.certificate_info.setText(
                "Łańcuch certyfikatów został wygenerowany i zapisany w 'cert_chain'.\n"
                "Zawiera:\n"
                "  - root_cert.pem: Certyfikat Root CA\n"
                "  - intermediate_cert.pem: Certyfikat Intermediate CA\n"
                "  - end_entity_cert.pem: Certyfikat końcowego podmiotu (End Entity)\n"
            )
        except Exception as e:
            self.ui.certificate_info.setText(f"Błąd podczas generowania łańcucha certyfikatów: {str(e)}")

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

#####HMAC#####
    def generate_hmac(self):
        """
        Generuje HMAC dla wybranego pliku PDF, zapisuje klucz w folderze 'data',
        i wyświetla szczegółowe informacje o kluczu.
        """
        if not self.selected_file:
            self.ui.label_2.setText("Nie wybrano pliku PDF.")
            return

        ensure_data_folder()  # Upewnia się, że folder 'data' istnieje

        # Generowanie lub załadowanie klucza HMAC
        try:
            key = load_hmac_key()
            key_message = "Klucz HMAC już istnieje i został załadowany."
        except FileNotFoundError:
            key_path = generate_hmac_key()
            key = load_hmac_key()
            key_message = f"Wygenerowano nowy klucz HMAC i zapisano w: {key_path}"

        # Oblicz HMAC
        hmac_value = calculate_hmac(self.selected_file, key)

        # Zapis HMAC
        hmac_path = os.path.join("data", "file.hmac")
        with open(hmac_path, "wb") as hmac_file:
            hmac_file.write(hmac_value)

        # Wyświetlanie szczegółowych informacji
        self.ui.certificate_info.setText(
            f"{key_message}\n"
            f"Szczegóły klucza:\n"
            f"  - Długość klucza: {len(key) * 8} bitów\n"
            f"  - Klucz (HEX): {key.hex()}\n\n"
            f"HMAC został wygenerowany i zapisany jako: {os.path.basename(hmac_path)}\n"
            f"Szczegóły HMAC:\n"
            f"  - Plik: {os.path.basename(self.selected_file)}\n"
            f"  - Lokalizacja pliku: {self.selected_file}\n"
            f"  - HMAC (HEX): {hmac_value.hex()}"
        )

    def verify_hmac(self):
        """
        Weryfikuje HMAC dla wybranego pliku PDF i wyświetla szczegółowe informacje.
        """
        if not self.selected_file:
            self.ui.label_2.setText("Nie wybrano pliku PDF.")
            return

        # Ścieżka do klucza HMAC i HMAC pliku
        hmac_path = os.path.join("data", "file.hmac")

        # Sprawdzenie, czy klucz HMAC istnieje
        try:
            key = load_hmac_key()
        except FileNotFoundError:
            self.ui.label_2.setText("Brak klucza HMAC. Wygeneruj go najpierw.")
            return

        # Sprawdzenie, czy HMAC został zapisany
        if not os.path.exists(hmac_path):
            self.ui.label_2.setText(f"Nie znaleziono pliku z HMAC w: {hmac_path}. Wygeneruj go najpierw.")
            return

        # Wczytaj zapisany HMAC
        with open(hmac_path, "rb") as hmac_file:
            saved_hmac = hmac_file.read()

        # Oblicz nowy HMAC dla pliku
        computed_hmac = calculate_hmac(self.selected_file, key)

        # Porównanie HMAC
        if saved_hmac == computed_hmac:
            self.ui.certificate_info.setText(
                "Weryfikacja HMAC zakończona pomyślnie.\n"
                "Szczegóły weryfikacji:\n"
                f"  - Algorytm: SHA256\n"
                f"  - Plik: {os.path.basename(self.selected_file)}\n"
                f"  - Lokalizacja pliku: {self.selected_file}\n"
                f"  - Klucz HMAC: {len(key) * 8} bitów\n"
                f"  - HMAC zapisany (HEX): {saved_hmac.hex()}\n"
                f"  - HMAC obliczony (HEX): {computed_hmac.hex()}"
            )
        else:
            self.ui.certificate_info.setText(
                "Weryfikacja HMAC nie powiodła się.\n"
                "Szczegóły:\n"
                f"  - Algorytm: SHA256\n"
                f"  - Plik: {os.path.basename(self.selected_file)}\n"
                f"  - Lokalizacja pliku: {self.selected_file}\n"
                f"  - Klucz HMAC: {len(key) * 8} bitów\n"
                f"  - HMAC zapisany (HEX): {saved_hmac.hex()}\n"
                f"  - HMAC obliczony (HEX): {computed_hmac.hex()}\n"
                "Plik został zmieniony lub użyto niewłaściwego klucza."
            )


if __name__ == "__main__":
    """
    Uruchamia aplikację PyQt5 do podpisów cyfrowych i obsługi certyfikatów.
    """
    ensure_data_folder()  # Tworzy folder 'data'
    ensure_cert_chain_folder()  # Tworzy folder 'cert_chain'
    
    app = QApplication(sys.argv)
    window = DigitalSignatureApp()
    window.show()
    sys.exit(app.exec())

