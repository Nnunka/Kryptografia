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
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        
###PRZYCISKI###
        self.ui.file.clicked.connect(self.wczytaj_plik)

        self.ui.szyfruj_transpozycja.clicked.connect(self.szyfruj_transpozycja)
        self.ui.odszyfruj_transpozycja.clicked.connect(self.odszyfruj_transpozycja)

        self.ui.szyfruj_monoalfabet.clicked.connect(self.szyfruj_monoalfabet)
        self.ui.odszyfruj__monoalfabet.clicked.connect(self.odszyfruj_monoalfabet)

        self.ui.szyfruj_des_blokowo.clicked.connect(self.szyfruj_des_blokowo)
        self.ui.odszyfruj__des_blokowo.clicked.connect(self.odszyfruj_des_blokowo)

        self.ui.szyfruj_des_strumieniowo.clicked.connect(self.szyfruj_des_strumieniowo)
        self.ui.odszyfruj__des_strumieniowo.clicked.connect(self.odszyfruj_des_strumieniowo)

        self.ui.szyfruj_aes_blokowo.clicked.connect(self.szyfruj_aes_blokowo)
        self.ui.odszyfruj__aes_blokowo.clicked.connect(self.odszyfruj_aes_blokowo)

        self.ui.szyfruj_aes_strumieniowo.clicked.connect(self.szyfruj_aes_strumieniowo)
        self.ui.odszyfruj__aes_strumieniowo.clicked.connect(self.odszyfruj_aes_strumieniowo)

        self.ui.szyfruj_rsa.clicked.connect(self.szyfruj_rsa)
        self.ui.odszyfruj_rsa.clicked.connect(self.odszyfruj_rsa)

        self.ui.klucz_hellman.clicked.connect(self.oblicz_klucze_diffie_hellman)
        self.ui.szyfruj_hellman.clicked.connect(self.szyfruj_hellman)
        self.ui.odszyfruj_hellman.clicked.connect(self.odszyfruj_hellman)

        # Inicjalizuj obiekty Diffie-Hellman jako None, będą tworzone dynamicznie
        self.diffie_hellman_alice = None
        self.diffie_hellman_bob = None

    def wczytaj_plik(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Wybierz plik", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            with open(file_name, 'r', encoding='utf-8') as file:
                tekst = file.read()
                self.ui.input.setPlainText(tekst)

###TRANSPOZYCJA###
    def szyfruj_transpozycja(self):
        tekst = self.ui.input.toPlainText()
        klucz = self.ui.klucz_transpozycja.value()
        szyfrowany = transpozycja.szyfruj(tekst, klucz)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_transpozycja(self):
        tekst = self.ui.input.toPlainText()
        klucz = self.ui.klucz_transpozycja.value()
        odszyfrowany = transpozycja.odszyfruj(tekst, klucz)
        self.ui.output.setPlainText(odszyfrowany)

###MONOALFABET###
    def szyfruj_monoalfabet(self):
        tekst = self.ui.input.toPlainText().lower()
        klucz = self.ui.klucz__monoalfabet.toPlainText().lower()
        szyfrowany = monoalfabet.szyfruj(tekst, klucz)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_monoalfabet(self):
        tekst = self.ui.input.toPlainText().lower()
        klucz = self.ui.klucz__monoalfabet.toPlainText().lower()
        odszyfrowany = monoalfabet.odszyfruj(tekst, klucz)
        self.ui.output.setPlainText(odszyfrowany)

### DES Blokowo ###
    def szyfruj_des_blokowo(self):
        tekst = self.ui.input.toPlainText()
        klucz = self.ui.klucz__des.toPlainText().encode('utf-8')
        if len(klucz) != 8:
            self.ui.output.setPlainText("Klucz DES musi mieć dokładnie 8 bajtów.")
            return
        des_cipher = DESCipher(klucz)
        szyfrowany = des_cipher.encrypt_block_mode(tekst)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_des_blokowo(self):
        szyfrowany = self.ui.input.toPlainText()
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
        tekst = self.ui.input.toPlainText()
        klucz = self.ui.klucz__des.toPlainText().encode('utf-8')
        if len(klucz) != 8:
            self.ui.output.setPlainText("Klucz DES musi mieć dokładnie 8 bajtów.")
            return
        des_cipher = DESCipher(klucz)
        szyfrowany = des_cipher.encrypt_stream_mode(tekst)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_des_strumieniowo(self):
        szyfrowany = self.ui.input.toPlainText()
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
        tekst = self.ui.input.toPlainText()
        klucz = self.ui.klucz__aes.toPlainText().encode('utf-8')
        if len(klucz) not in [16, 24, 32]:
            self.ui.output.setPlainText("Klucz AES musi mieć 16, 24 lub 32 bajty.")
            return
        aes_cipher = AESCipher(klucz)
        szyfrowany = aes_cipher.encrypt_block_mode(tekst)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_aes_blokowo(self):
        szyfrowany = self.ui.input.toPlainText()
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
        tekst = self.ui.input.toPlainText()
        klucz = self.ui.klucz__aes.toPlainText().encode('utf-8')
        if len(klucz) not in [16, 24, 32]:
            self.ui.output.setPlainText("Klucz AES musi mieć 16, 24 lub 32 bajty.")
            return
        aes_cipher = AESCipher(klucz)
        szyfrowany = aes_cipher.encrypt_stream_mode(tekst)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_aes_strumieniowo(self):
        szyfrowany = self.ui.input.toPlainText()
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
        try:
            # Pobranie wartości p i q z pól GUI
            p = self.ui.p_rsa.value()
            q = self.ui.q_rsa.value()

            # Utworzenie obiektu RSACipher
            rsa_cipher = RSACipher(p, q)

            # Pobranie tekstu do zaszyfrowania
            tekst = self.ui.input.toPlainText()

            # Szyfrowanie
            szyfrowany = rsa_cipher.encrypt(tekst)
            szyfrowany_str = " ".join(map(str, szyfrowany))  # Konwersja listy do ciągu

            # Wyświetlenie wyników w polu output
            self.ui.output.setPlainText(
                f"{szyfrowany_str}\nKlucz publiczny: {rsa_cipher.public_key}"
            )

            # Przechowujemy klucz prywatny w pamięci dla późniejszego odszyfrowania
            self.rsa_cipher = rsa_cipher

        except Exception as e:
            self.ui.output.setPlainText(f"Błąd szyfrowania RSA: {str(e)}")


    def odszyfruj_rsa(self):
        try:
            # Pobranie szyfrogramu z pola input
            szyfrogram = self.ui.input.toPlainText()

            # Konwersja szyfrogramu na listę liczb
            ciphertext = list(map(int, szyfrogram.split()))

            # Użycie zapisanego klucza prywatnego do odszyfrowania
            odszyfrowany = self.rsa_cipher.decrypt(ciphertext)

            # Wyświetlenie odszyfrowanego tekstu
            self.ui.output.setPlainText(f"{odszyfrowany}")

        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania RSA: {str(e)}")


 ### DIFFIE-HELLMAN ###
    def oblicz_klucze_diffie_hellman(self):
        try:
            # Pobranie wartości p i g z GUI
            p = self.ui.p_hellman.value()
            g = self.ui.g_hellman.value()

            # Walidacja
            if not isprime(p):
                self.ui.output.setPlainText("p musi być liczbą pierwszą.")
                return
            if not (1 < g < p):
                self.ui.output.setPlainText("g musi być większe niż 1 i mniejsze niż p.")
                return

            # Inicjalizacja obiektów Diffie-Hellmana
            self.diffie_hellman_alice = DiffieHellman(p, g)
            self.diffie_hellman_bob = DiffieHellman(p, g)

            # Wyświetlenie kluczy publicznych
            self.ui.klucz__monoalfabet_2.setPlainText(str(self.diffie_hellman_alice.public_key))
            self.ui.klucz__bob.setPlainText(str(self.diffie_hellman_bob.public_key))
            self.ui.output.setPlainText("Klucze publiczne zostały wygenerowane.")
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd podczas obliczania kluczy: {str(e)}")

    def szyfruj_hellman(self):
        try:
            if self.diffie_hellman_alice is None or self.diffie_hellman_bob is None:
                self.ui.output.setPlainText("Najpierw oblicz klucze publiczne.")
                return

            # Pobranie tekstu do zaszyfrowania
            tekst = self.ui.input.toPlainText()
            if not tekst:
                self.ui.output.setPlainText("Podaj tekst do zaszyfrowania.")
                return

            # Obliczenie wspólnego sekretu
            alice_shared_secret = self.diffie_hellman_alice.compute_shared_secret(self.diffie_hellman_bob.public_key)
            alice_key = DiffieHellman.derive_key(alice_shared_secret)

            # Szyfrowanie wiadomości
            szyfrowany = DiffieHellman.encrypt_message(tekst, alice_key)

            # Wyświetlenie zaszyfrowanej wiadomości
            self.ui.output.setPlainText(szyfrowany)

        except Exception as e:
            self.ui.output.setPlainText(f"Błąd szyfrowania Diffie-Hellman: {str(e)}")

    def odszyfruj_hellman(self):
        try:
            if self.diffie_hellman_alice is None or self.diffie_hellman_bob is None:
                self.ui.output.setPlainText("Najpierw oblicz klucze publiczne.")
                return

            # Pobranie szyfrogramu
            szyfrowany = self.ui.input.toPlainText()
            if not szyfrowany:
                self.ui.output.setPlainText("Podaj szyfrogram do odszyfrowania.")
                return

            # Obliczenie wspólnego sekretu
            bob_shared_secret = self.diffie_hellman_bob.compute_shared_secret(self.diffie_hellman_alice.public_key)
            bob_key = DiffieHellman.derive_key(bob_shared_secret)

            # Odszyfrowanie wiadomości
            odszyfrowany = DiffieHellman.decrypt_message(szyfrowany, bob_key)

            # Wyświetlenie odszyfrowanej wiadomości
            self.ui.output.setPlainText(odszyfrowany)

        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania Diffie-Hellman: {str(e)}")



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Projekt()
    window.show()
    sys.exit(app.exec_())
