# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(501, 817)
        MainWindow.setMaximumSize(QtCore.QSize(800, 16777215))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 10, 380, 30))
        self.label.setMaximumSize(QtCore.QSize(380, 30))
        self.label.setObjectName("label")
        self.input = QtWidgets.QTextEdit(self.centralwidget)
        self.input.setGeometry(QtCore.QRect(10, 40, 371, 40))
        self.input.setObjectName("input")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(10, 90, 231, 30))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(10, 120, 100, 30))
        self.label_3.setObjectName("label_3")
        self.klucz_transpozycja = QtWidgets.QSpinBox(self.centralwidget)
        self.klucz_transpozycja.setGeometry(QtCore.QRect(120, 120, 100, 30))
        self.klucz_transpozycja.setMinimum(1)
        self.klucz_transpozycja.setObjectName("klucz_transpozycja")
        self.szyfruj_transpozycja = QtWidgets.QPushButton(self.centralwidget)
        self.szyfruj_transpozycja.setGeometry(QtCore.QRect(10, 170, 100, 30))
        self.szyfruj_transpozycja.setObjectName("szyfruj_transpozycja")
        self.odszyfruj_transpozycja = QtWidgets.QPushButton(self.centralwidget)
        self.odszyfruj_transpozycja.setGeometry(QtCore.QRect(120, 170, 100, 30))
        self.odszyfruj_transpozycja.setObjectName("odszyfruj_transpozycja")
        self.output = QtWidgets.QTextEdit(self.centralwidget)
        self.output.setGeometry(QtCore.QRect(10, 640, 481, 161))
        self.output.setObjectName("output")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(10, 210, 231, 30))
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(10, 240, 100, 30))
        self.label_5.setObjectName("label_5")
        self.klucz__monoalfabet = QtWidgets.QTextEdit(self.centralwidget)
        self.klucz__monoalfabet.setGeometry(QtCore.QRect(120, 240, 100, 30))
        self.klucz__monoalfabet.setObjectName("klucz__monoalfabet")
        self.odszyfruj__monoalfabet = QtWidgets.QPushButton(self.centralwidget)
        self.odszyfruj__monoalfabet.setGeometry(QtCore.QRect(120, 280, 100, 30))
        self.odszyfruj__monoalfabet.setObjectName("odszyfruj__monoalfabet")
        self.szyfruj_monoalfabet = QtWidgets.QPushButton(self.centralwidget)
        self.szyfruj_monoalfabet.setGeometry(QtCore.QRect(10, 280, 100, 30))
        self.szyfruj_monoalfabet.setObjectName("szyfruj_monoalfabet")
        self.file = QtWidgets.QPushButton(self.centralwidget)
        self.file.setGeometry(QtCore.QRect(390, 40, 100, 40))
        self.file.setObjectName("file")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(10, 320, 231, 30))
        self.label_6.setObjectName("label_6")
        self.szyfruj_des_blokowo = QtWidgets.QPushButton(self.centralwidget)
        self.szyfruj_des_blokowo.setGeometry(QtCore.QRect(10, 390, 100, 30))
        self.szyfruj_des_blokowo.setObjectName("szyfruj_des_blokowo")
        self.odszyfruj__des_blokowo = QtWidgets.QPushButton(self.centralwidget)
        self.odszyfruj__des_blokowo.setGeometry(QtCore.QRect(10, 430, 100, 30))
        self.odszyfruj__des_blokowo.setObjectName("odszyfruj__des_blokowo")
        self.klucz__des = QtWidgets.QTextEdit(self.centralwidget)
        self.klucz__des.setGeometry(QtCore.QRect(120, 350, 121, 30))
        self.klucz__des.setObjectName("klucz__des")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setGeometry(QtCore.QRect(10, 350, 100, 30))
        self.label_7.setObjectName("label_7")
        self.odszyfruj__des_strumieniowo = QtWidgets.QPushButton(self.centralwidget)
        self.odszyfruj__des_strumieniowo.setGeometry(QtCore.QRect(120, 430, 121, 30))
        self.odszyfruj__des_strumieniowo.setObjectName("odszyfruj__des_strumieniowo")
        self.szyfruj_des_strumieniowo = QtWidgets.QPushButton(self.centralwidget)
        self.szyfruj_des_strumieniowo.setGeometry(QtCore.QRect(120, 390, 121, 30))
        self.szyfruj_des_strumieniowo.setObjectName("szyfruj_des_strumieniowo")
        self.label_8 = QtWidgets.QLabel(self.centralwidget)
        self.label_8.setGeometry(QtCore.QRect(10, 470, 231, 30))
        self.label_8.setObjectName("label_8")
        self.szyfruj_aes_blokowo = QtWidgets.QPushButton(self.centralwidget)
        self.szyfruj_aes_blokowo.setGeometry(QtCore.QRect(10, 540, 100, 30))
        self.szyfruj_aes_blokowo.setObjectName("szyfruj_aes_blokowo")
        self.odszyfruj__aes_blokowo = QtWidgets.QPushButton(self.centralwidget)
        self.odszyfruj__aes_blokowo.setGeometry(QtCore.QRect(10, 580, 100, 30))
        self.odszyfruj__aes_blokowo.setObjectName("odszyfruj__aes_blokowo")
        self.klucz__aes = QtWidgets.QTextEdit(self.centralwidget)
        self.klucz__aes.setGeometry(QtCore.QRect(120, 500, 121, 30))
        self.klucz__aes.setObjectName("klucz__aes")
        self.label_9 = QtWidgets.QLabel(self.centralwidget)
        self.label_9.setGeometry(QtCore.QRect(10, 500, 100, 30))
        self.label_9.setObjectName("label_9")
        self.odszyfruj__aes_strumieniowo = QtWidgets.QPushButton(self.centralwidget)
        self.odszyfruj__aes_strumieniowo.setGeometry(QtCore.QRect(120, 580, 121, 30))
        self.odszyfruj__aes_strumieniowo.setObjectName("odszyfruj__aes_strumieniowo")
        self.szyfruj_aes_strumieniowo = QtWidgets.QPushButton(self.centralwidget)
        self.szyfruj_aes_strumieniowo.setGeometry(QtCore.QRect(120, 540, 121, 30))
        self.szyfruj_aes_strumieniowo.setObjectName("szyfruj_aes_strumieniowo")
        self.label_10 = QtWidgets.QLabel(self.centralwidget)
        self.label_10.setGeometry(QtCore.QRect(260, 90, 231, 30))
        self.label_10.setObjectName("label_10")
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setGeometry(QtCore.QRect(240, 90, 20, 531))
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.line_2 = QtWidgets.QFrame(self.centralwidget)
        self.line_2.setGeometry(QtCore.QRect(10, 620, 481, 20))
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.odszyfruj_rsa = QtWidgets.QPushButton(self.centralwidget)
        self.odszyfruj_rsa.setGeometry(QtCore.QRect(370, 120, 100, 30))
        self.odszyfruj_rsa.setObjectName("odszyfruj_rsa")
        self.szyfruj_rsa = QtWidgets.QPushButton(self.centralwidget)
        self.szyfruj_rsa.setGeometry(QtCore.QRect(260, 120, 100, 30))
        self.szyfruj_rsa.setObjectName("szyfruj_rsa")
        self.label_11 = QtWidgets.QLabel(self.centralwidget)
        self.label_11.setGeometry(QtCore.QRect(260, 160, 231, 30))
        self.label_11.setObjectName("label_11")
        self.odszyfruj_hellman = QtWidgets.QPushButton(self.centralwidget)
        self.odszyfruj_hellman.setGeometry(QtCore.QRect(370, 190, 100, 30))
        self.odszyfruj_hellman.setObjectName("odszyfruj_hellman")
        self.szyfruj_hellman = QtWidgets.QPushButton(self.centralwidget)
        self.szyfruj_hellman.setGeometry(QtCore.QRect(260, 190, 100, 30))
        self.szyfruj_hellman.setObjectName("szyfruj_hellman")
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "Podaj tekst:"))
        self.label_2.setText(_translate("MainWindow", "TRANSPOZYCJA"))
        self.label_3.setText(_translate("MainWindow", "Podaj klucz:"))
        self.szyfruj_transpozycja.setText(_translate("MainWindow", "Szyfruj"))
        self.odszyfruj_transpozycja.setText(_translate("MainWindow", "Odszyfruj"))
        self.label_4.setText(_translate("MainWindow", "MONOALFABET"))
        self.label_5.setText(_translate("MainWindow", "Podaj klucz:"))
        self.odszyfruj__monoalfabet.setText(_translate("MainWindow", "Odszyfruj"))
        self.szyfruj_monoalfabet.setText(_translate("MainWindow", "Szyfruj"))
        self.file.setText(_translate("MainWindow", "Wczytaj z pliku"))
        self.label_6.setText(_translate("MainWindow", "DES"))
        self.szyfruj_des_blokowo.setText(_translate("MainWindow", "Szyfruj blokowo"))
        self.odszyfruj__des_blokowo.setText(_translate("MainWindow", "Odszyfruj blokowo"))
        self.label_7.setText(_translate("MainWindow", "Podaj klucz:"))
        self.odszyfruj__des_strumieniowo.setText(_translate("MainWindow", "Odszyfruj strumieniowo"))
        self.szyfruj_des_strumieniowo.setText(_translate("MainWindow", "Szyfruj strumieniowo"))
        self.label_8.setText(_translate("MainWindow", "AES"))
        self.szyfruj_aes_blokowo.setText(_translate("MainWindow", "Szyfruj blokowo"))
        self.odszyfruj__aes_blokowo.setText(_translate("MainWindow", "Odszyfruj blokowo"))
        self.label_9.setText(_translate("MainWindow", "Podaj klucz:"))
        self.odszyfruj__aes_strumieniowo.setText(_translate("MainWindow", "Odszyfruj strumieniowo"))
        self.szyfruj_aes_strumieniowo.setText(_translate("MainWindow", "Szyfruj strumieniowo"))
        self.label_10.setText(_translate("MainWindow", "RSA"))
        self.odszyfruj_rsa.setText(_translate("MainWindow", "Odszyfruj"))
        self.szyfruj_rsa.setText(_translate("MainWindow", "Szyfruj"))
        self.label_11.setText(_translate("MainWindow", "DIFFIE-HELLMAN"))
        self.odszyfruj_hellman.setText(_translate("MainWindow", "Odszyfruj"))
        self.szyfruj_hellman.setText(_translate("MainWindow", "Szyfruj"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
