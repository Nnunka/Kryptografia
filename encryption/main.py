import os
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
from MainWindow import Ui_MainWindow
import transpozycja  
import monoalfabet
from sympy import isprime
from des import DESCipher
from aes import AESCipher
from rsa import RSACipher
from diffie_hellman import DiffieHellman


class Projekt(QMainWindow):
    """
    Klasa głównego okna aplikacji implementująca różne algorytmy szyfrowania 
    z interfejsem graficznym stworzonym w PyQt5.
    """

    def __init__(self):
        """
        Inicjalizacja głównego okna aplikacji. Konfiguracja interfejsu i podłączenie przycisków.
        """
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        ### PRZYCISKI ###
        # Podłączanie akcji do odpowiednich przycisków w GUI
        self.ui.file.clicked.connect(self.wczytaj_plik)

        # Transpozycja
        self.ui.szyfruj_transpozycja.clicked.connect(self.szyfruj_transpozycja)
        self.ui.odszyfruj_transpozycja.clicked.connect(self.odszyfruj_transpozycja)

        # Monoalfabet
        self.ui.szyfruj_monoalfabet.clicked.connect(self.szyfruj_monoalfabet)
        self.ui.odszyfruj__monoalfabet.clicked.connect(self.odszyfruj_monoalfabet)

        # DES
        self.ui.szyfruj_des_blokowo.clicked.connect(self.szyfruj_des_blokowo)
        self.ui.odszyfruj__des_blokowo.clicked.connect(self.odszyfruj_des_blokowo)
        self.ui.szyfruj_des_strumieniowo.clicked.connect(self.szyfruj_des_strumieniowo)
        self.ui.odszyfruj__des_strumieniowo.clicked.connect(self.odszyfruj_des_strumieniowo)

        # AES
        self.ui.szyfruj_aes_blokowo.clicked.connect(self.szyfruj_aes_blokowo)
        self.ui.odszyfruj__aes_blokowo.clicked.connect(self.odszyfruj_aes_blokowo)
        self.ui.szyfruj_aes_strumieniowo.clicked.connect(self.szyfruj_aes_strumieniowo)
        self.ui.odszyfruj__aes_strumieniowo.clicked.connect(self.odszyfruj_aes_strumieniowo)

        # RSA
        self.ui.szyfruj_rsa.clicked.connect(self.szyfruj_rsa)
        self.ui.odszyfruj_rsa.clicked.connect(self.odszyfruj_rsa)

        # Diffie-Hellman
        self.ui.klucz_hellman.clicked.connect(self.oblicz_klucze_diffie_hellman)
        self.ui.szyfruj_hellman.clicked.connect(self.szyfruj_hellman)
        self.ui.odszyfruj_hellman.clicked.connect(self.odszyfruj_hellman)

        # Inicjalizacja obiektów Diffie-Hellman jako None
        self.diffie_hellman_alice = None
        self.diffie_hellman_bob = None

    @staticmethod
    def resource_path(relative_path):
        """
        Funkcja do obsługi poprawnych ścieżek w środowisku PyInstaller.
        """
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_path, relative_path)
 

    def wczytaj_plik(self):
        """
        Obsługuje wczytywanie pliku z systemu plików i wyświetla jego zawartość w polu tekstowym.
        """
        try:
            # QFileDialog pozwala użytkownikowi wybrać plik
            file_name, _ = QFileDialog.getOpenFileName(self, "Wybierz plik", "", "Text Files (*.txt);;All Files (*)")
            
            if file_name:
                # Otwieramy plik wybrany przez użytkownika
                with open(file_name, 'r', encoding='utf-8') as file:
                    tekst = file.read()
                    self.ui.input.setPlainText(tekst)
            else:
                self.ui.output.setPlainText("Nie wybrano żadnego pliku.")
        except Exception as e:
            # Obsługa błędów - przydatne w przypadku problemów z dostępem do pliku
            self.ui.output.setPlainText(f"Błąd podczas wczytywania pliku: {str(e)}")

    
    def sprawdz_puste_pole(self, tekst):
        if not tekst.strip():
            self.ui.output.setPlainText("Pole tekstowe jest puste. Wprowadź tekst do szyfrowania.")
            return False
        return True

    ### Transpozycja ###
    def szyfruj_transpozycja(self):
        """
        Szyfruje tekst za pomocą szyfru transpozycyjnego na podstawie klucza.
        """
        tekst = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(tekst):
            return
        klucz = self.ui.klucz_transpozycja.value()
        szyfrowany = transpozycja.szyfruj(tekst, klucz)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_transpozycja(self):
        """
        Odszyfrowuje tekst zaszyfrowany szyfrem transpozycyjnym na podstawie klucza.
        """
        tekst = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(tekst):
            return
        klucz = self.ui.klucz_transpozycja.value()
        odszyfrowany = transpozycja.odszyfruj(tekst, klucz)
        self.ui.output.setPlainText(odszyfrowany)

    ### Monoalfabet ###
    def szyfruj_monoalfabet(self):
        """
        Szyfruje tekst za pomocą szyfru monoalfabetycznego z użyciem klucza.
        """
        tekst = self.ui.input.toPlainText().lower()
        if not self.sprawdz_puste_pole(tekst):
            return
        klucz = self.ui.klucz__monoalfabet.toPlainText().lower()
        szyfrowany = monoalfabet.szyfruj(tekst, klucz)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_monoalfabet(self):
        """
        Odszyfrowuje tekst zaszyfrowany szyfrem monoalfabetycznym z użyciem klucza.
        """
        tekst = self.ui.input.toPlainText().lower()
        if not self.sprawdz_puste_pole(tekst):
            return
        klucz = self.ui.klucz__monoalfabet.toPlainText().lower()
        odszyfrowany = monoalfabet.odszyfruj(tekst, klucz)
        self.ui.output.setPlainText(odszyfrowany)

   ### DES Blokowo ###
    def szyfruj_des_blokowo(self):
        """
        Szyfruje tekst za pomocą algorytmu DES w trybie blokowym.
        """
        tekst = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(tekst):
            return
        klucz = self.ui.klucz__des.toPlainText().encode('utf-8')
        if len(klucz) != 8:
            self.ui.output.setPlainText("Klucz DES musi mieć dokładnie 8 bajtów.")
            return
        des_cipher = DESCipher(klucz)
        szyfrowany = des_cipher.encrypt_block_mode(tekst)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_des_blokowo(self):
        """
        Odszyfrowuje tekst zaszyfrowany za pomocą algorytmu DES w trybie blokowym.
        """
        szyfrowany = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(szyfrowany):
            return
        klucz = self.ui.klucz__des.toPlainText().encode('utf-8')
        if len(klucz) != 8:
            self.ui.output.setPlainText("Klucz DES musi mieć dokładnie 8 bajtów.")
            return
        des_cipher = DESCipher(klucz)
        try:
            odszyfrowany = des_cipher.decrypt_block_mode(szyfrowany)
            self.ui.output.setPlainText(odszyfrowany)
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania: {str(e)}")

    ### DES Strumieniowo ###
    def szyfruj_des_strumieniowo(self):
        """
        Szyfruje tekst za pomocą algorytmu DES w trybie strumieniowym.
        """
        tekst = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(tekst):
            return
        klucz = self.ui.klucz__des.toPlainText().encode('utf-8')
        if len(klucz) != 8:
            self.ui.output.setPlainText("Klucz DES musi mieć dokładnie 8 bajtów.")
            return
        des_cipher = DESCipher(klucz)
        szyfrowany = des_cipher.encrypt_stream_mode(tekst)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_des_strumieniowo(self):
        """
        Odszyfrowuje tekst zaszyfrowany za pomocą algorytmu DES w trybie strumieniowym.
        """
        szyfrowany = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(szyfrowany):
            return
        klucz = self.ui.klucz__des.toPlainText().encode('utf-8')
        if len(klucz) != 8:
            self.ui.output.setPlainText("Klucz DES musi mieć dokładnie 8 bajtów.")
            return
        des_cipher = DESCipher(klucz)
        try:
            odszyfrowany = des_cipher.decrypt_stream_mode(szyfrowany)
            self.ui.output.setPlainText(odszyfrowany)
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania: {str(e)}")

    ### AES Blokowo ###
    def szyfruj_aes_blokowo(self):
        """
        Szyfruje tekst za pomocą algorytmu AES w trybie blokowym.
        """
        tekst = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(tekst):
            return
        klucz = self.ui.klucz__aes.toPlainText().encode('utf-8')
        if len(klucz) not in [16, 24, 32]:
            self.ui.output.setPlainText("Klucz AES musi mieć 16, 24 lub 32 bajty.")
            return
        aes_cipher = AESCipher(klucz)
        szyfrowany = aes_cipher.encrypt_block_mode(tekst)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_aes_blokowo(self):
        """
        Odszyfrowuje tekst zaszyfrowany za pomocą algorytmu AES w trybie blokowym.
        """
        szyfrowany = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(szyfrowany):
            return
        klucz = self.ui.klucz__aes.toPlainText().encode('utf-8')
        if len(klucz) not in [16, 24, 32]:
            self.ui.output.setPlainText("Klucz AES musi mieć 16, 24 lub 32 bajty.")
            return
        aes_cipher = AESCipher(klucz)
        try:
            odszyfrowany = aes_cipher.decrypt_block_mode(szyfrowany)
            self.ui.output.setPlainText(odszyfrowany)
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania: {str(e)}")

    ### AES Strumieniowo ###
    def szyfruj_aes_strumieniowo(self):
        """
        Szyfruje tekst za pomocą algorytmu AES w trybie strumieniowym.
        """
        tekst = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(tekst):
            return
        klucz = self.ui.klucz__aes.toPlainText().encode('utf-8')
        if len(klucz) not in [16, 24, 32]:
            self.ui.output.setPlainText("Klucz AES musi mieć 16, 24 lub 32 bajty.")
            return
        aes_cipher = AESCipher(klucz)
        szyfrowany = aes_cipher.encrypt_stream_mode(tekst)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_aes_strumieniowo(self):
        """
        Odszyfrowuje tekst zaszyfrowany za pomocą algorytmu AES w trybie strumieniowym.
        """
        szyfrowany = self.ui.input.toPlainText()
        if not self.sprawdz_puste_pole(szyfrowany):
            return
        klucz = self.ui.klucz__aes.toPlainText().encode('utf-8')
        if len(klucz) not in [16, 24, 32]:
            self.ui.output.setPlainText("Klucz AES musi mieć 16, 24 lub 32 bajty.")
            return
        aes_cipher = AESCipher(klucz)
        try:
            odszyfrowany = aes_cipher.decrypt_stream_mode(szyfrowany)
            self.ui.output.setPlainText(odszyfrowany)
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania: {str(e)}")

### RSA ###
    def szyfruj_rsa(self):
        """
        Szyfruje tekst za pomocą algorytmu RSA i wyświetla klucz publiczny w polu klucz_rsa.
        """
        rsa_cipher = RSACipher()  # Inicjalizacja algorytmu RSA
        tekst = self.ui.input.toPlainText()  # Pobierz tekst do zaszyfrowania

        try:
            # Szyfrowanie tekstu
            szyfrowany = rsa_cipher.encrypt(tekst)
            szyfrowany_str = " ".join(map(str, szyfrowany))  # Konwertuj listę na ciąg tekstowy

            # Wyświetlanie zaszyfrowanego tekstu w polu `output`
            self.ui.output.setPlainText(szyfrowany_str)

            # Zapis klucza prywatnego
            self.rsa_private_key = rsa_cipher.private_key

            # Wyświetlanie klucza publicznego w polu `klucz_rsa`
            public_key_str = f"N:{rsa_cipher.public_key[0]}, E: {rsa_cipher.public_key[1]}"
            self.ui.klucz__rsa.setPlainText(public_key_str)

        except Exception as e:
            self.ui.output.setPlainText(f"Błąd szyfrowania RSA: {str(e)}")



    def odszyfruj_rsa(self):
        """
        Odszyfruje tekst za pomocą algorytmu RSA.
        """
        try:
            szyfrowany = self.ui.input.toPlainText()
            ciphertext = list(map(int, szyfrowany.split()))  
            rsa_cipher = RSACipher()
            rsa_cipher.private_key = self.rsa_private_key 
            odszyfrowany = rsa_cipher.decrypt(ciphertext)
            self.ui.output.setPlainText(odszyfrowany)
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania: {str(e)}")

    ### Diffie-Hellman ###
    def oblicz_klucze_diffie_hellman(self):
        """
        Oblicza klucze publiczne i inicjalizuje obiekty Diffie-Hellman.
        """
        try:
            p = self.ui.p_hellman.value()
            g = self.ui.g_hellman.value()
            
            # Sprawdzanie, czy p jest liczbą pierwszą
            if not isprime(p):
                self.ui.output.setPlainText("Błąd: 'p' musi być liczbą pierwszą.")
                return
            
            # Sprawdzanie, czy g jest w zakresie
            if not (1 < g < p):
                self.ui.output.setPlainText("Błąd: 'g' musi być większe niż 1 i mniejsze niż 'p'.")
                return

            # Inicjalizacja obiektów Diffie-Hellman
            self.diffie_hellman_alice = DiffieHellman(p, g)
            self.diffie_hellman_bob = DiffieHellman(p, g)

            # Wyświetlanie kluczy publicznych
            self.ui.klucz__monoalfabet_2.setPlainText(str(self.diffie_hellman_alice.public_key))
            self.ui.klucz__bob.setPlainText(str(self.diffie_hellman_bob.public_key))
            self.ui.output.setPlainText("Klucze publiczne zostały wygenerowane pomyślnie.")

        except ValueError as e:
            self.ui.output.setPlainText(f"Błąd podczas obliczania kluczy: {str(e)}")
        except Exception as e:
            self.ui.output.setPlainText(f"Nieoczekiwany błąd: {str(e)}")


    def szyfruj_hellman(self):
        """
        Szyfruje wiadomość z wykorzystaniem wspólnego klucza Diffie-Hellman.
        """
        try:
            if self.diffie_hellman_alice is None or self.diffie_hellman_bob is None:
                self.ui.output.setPlainText("Najpierw oblicz klucze publiczne.")
                return
            tekst = self.ui.input.toPlainText()
            if not self.sprawdz_puste_pole(tekst):
                return
            alice_shared_secret = self.diffie_hellman_alice.compute_shared_secret(self.diffie_hellman_bob.public_key)
            alice_key = DiffieHellman.derive_key(alice_shared_secret)
            szyfrowany = DiffieHellman.encrypt_message(tekst, alice_key)
            self.ui.output.setPlainText(szyfrowany)
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd szyfrowania Diffie-Hellman: {str(e)}")

    def odszyfruj_hellman(self):
        """
        Odszyfrowuje wiadomość z wykorzystaniem wspólnego klucza Diffie-Hellman.
        """
        try:
            if self.diffie_hellman_alice is None or self.diffie_hellman_bob is None:
                self.ui.output.setPlainText("Najpierw oblicz klucze publiczne.")
                return
            szyfrowany = self.ui.input.toPlainText()
            if not self.sprawdz_puste_pole(szyfrowany):
                return
            bob_shared_secret = self.diffie_hellman_bob.compute_shared_secret(self.diffie_hellman_alice.public_key)
            bob_key = DiffieHellman.derive_key(bob_shared_secret)
            odszyfrowany = DiffieHellman.decrypt_message(szyfrowany, bob_key)
            self.ui.output.setPlainText(odszyfrowany)
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania Diffie-Hellman: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Projekt()
    window.show()
    sys.exit(app.exec_())
