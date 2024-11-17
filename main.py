import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
from MainWindow import Ui_MainWindow
import transpozycja  
import monoalfabet
from des import DESCipher
from aes import AESCipher
from rsa import RSACipher
from diffie_hellman import DiffieHellman

class Projekt(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.diffie_hellman_alice = DiffieHellman()
        self.diffie_hellman_bob = DiffieHellman()

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

        self.ui.szyfruj_hellman.clicked.connect(self.szyfruj_hellman)
        self.ui.odszyfruj_hellman.clicked.connect(self.odszyfruj_hellman)

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
        rsa_cipher = RSACipher()
        tekst = self.ui.input.toPlainText()
        try:
            szyfrowany = rsa_cipher.encrypt(tekst)
            szyfrowany_str = " ".join(map(str, szyfrowany))  # Zamiana listy liczb na ciąg
            self.ui.output.setPlainText(
                f"{szyfrowany_str}\nKlucz publiczny: {rsa_cipher.public_key}"
            )
            self.rsa_private_key = rsa_cipher.private_key  # Przechowujemy klucz prywatny
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd szyfrowania: {str(e)}")

    def odszyfruj_rsa(self):
        try:
            szyfrowany = self.ui.input.toPlainText()
            ciphertext = list(map(int, szyfrowany.split()))  # Konwersja ciągu na listę liczb
            rsa_cipher = RSACipher()
            rsa_cipher.private_key = self.rsa_private_key  # Użycie klucza prywatnego
            odszyfrowany = rsa_cipher.decrypt(ciphertext)
            self.ui.output.setPlainText(odszyfrowany)
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania: {str(e)}")

### DIFFIE-HELLMAN ###
    def szyfruj_hellman(self):
        tekst = self.ui.input.toPlainText()

        # Wymiana kluczy
        alice_public_key = self.diffie_hellman_alice.public_key
        bob_public_key = self.diffie_hellman_bob.public_key

        # Obliczanie wspólnego sekretu
        alice_shared_secret = self.diffie_hellman_alice.compute_shared_secret(bob_public_key)
        alice_key = DiffieHellman.derive_key(alice_shared_secret)

        # Szyfrowanie wiadomości
        try:
            szyfrowany = DiffieHellman.encrypt_message(tekst, alice_key)
            self.ui.output.setPlainText(
                f"{szyfrowany}\nAlice Public Key: {alice_public_key}\nBob Public Key: {bob_public_key}"
            )
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd szyfrowania Diffie-Hellman: {str(e)}")

    def odszyfruj_hellman(self):
        szyfrowany = self.ui.input.toPlainText()

        # Wymiana kluczy
        alice_public_key = self.diffie_hellman_alice.public_key
        bob_shared_secret = self.diffie_hellman_bob.compute_shared_secret(alice_public_key)
        bob_key = DiffieHellman.derive_key(bob_shared_secret)

        # Odszyfrowanie wiadomości
        try:
            odszyfrowany = DiffieHellman.decrypt_message(szyfrowany, bob_key)
            self.ui.output.setPlainText(odszyfrowany)
        except Exception as e:
            self.ui.output.setPlainText(f"Błąd odszyfrowania Diffie-Hellman: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Projekt()
    window.show()
    sys.exit(app.exec_())
