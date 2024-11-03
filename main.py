import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
from MainWindow import Ui_MainWindow
import transpozycja  
import monoalfabet
from des import DESCipher
from aes import AESCipher

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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Projekt()
    window.show()
    sys.exit(app.exec_())
