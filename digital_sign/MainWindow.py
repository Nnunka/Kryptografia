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
        MainWindow.resize(500, 600)
        MainWindow.setMaximumSize(QtCore.QSize(500, 16777215))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.select_file = QtWidgets.QPushButton(self.centralwidget)
        self.select_file.setGeometry(QtCore.QRect(10, 40, 480, 23))
        self.select_file.setObjectName("select_file")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 10, 481, 21))
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.generate_keys = QtWidgets.QPushButton(self.centralwidget)
        self.generate_keys.setGeometry(QtCore.QRect(10, 70, 480, 23))
        self.generate_keys.setObjectName("generate_keys")
        self.sing_file = QtWidgets.QPushButton(self.centralwidget)
        self.sing_file.setGeometry(QtCore.QRect(10, 100, 480, 23))
        self.sing_file.setObjectName("sing_file")
        self.verify_signature = QtWidgets.QPushButton(self.centralwidget)
        self.verify_signature.setGeometry(QtCore.QRect(10, 130, 480, 23))
        self.verify_signature.setObjectName("verify_signature")
        self.load_certificate = QtWidgets.QPushButton(self.centralwidget)
        self.load_certificate.setGeometry(QtCore.QRect(10, 160, 480, 23))
        self.load_certificate.setObjectName("load_certificate")
        self.certificate_info = QtWidgets.QTextEdit(self.centralwidget)
        self.certificate_info.setGeometry(QtCore.QRect(13, 190, 481, 341))
        self.certificate_info.setObjectName("certificate_info")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(10, 550, 481, 21))
        self.label_2.setText("")
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName("label_2")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.select_file.setText(_translate("MainWindow", "Wybierz plik PDF"))
        self.label.setText(_translate("MainWindow", "Nie wybrano pliku"))
        self.generate_keys.setText(_translate("MainWindow", "Wygeneruj klucze"))
        self.sing_file.setText(_translate("MainWindow", "Podpisz plik PDF"))
        self.verify_signature.setText(_translate("MainWindow", "Zweryfikuj podpis"))
        self.load_certificate.setText(_translate("MainWindow", "Przeglądaj certyfikat X.509"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
