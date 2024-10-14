import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
from MainWindow import Ui_MainWindow
import transpozycja  
import monoalfabet

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
        slowo_klucz = self.ui.klucz__monoalfabet.toPlainText().lower()
        szyfrowany = monoalfabet.szyfruj(tekst, slowo_klucz)
        self.ui.output.setPlainText(szyfrowany)

    def odszyfruj_monoalfabet(self):
        tekst = self.ui.input.toPlainText().lower()
        slowo_klucz = self.ui.klucz__monoalfabet.toPlainText().lower()
        odszyfrowany = monoalfabet.odszyfruj(tekst, slowo_klucz)
        self.ui.output.setPlainText(odszyfrowany)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Projekt()
    window.show()
    sys.exit(app.exec_())
