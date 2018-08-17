# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'SAST_Setting.ui'
#
# Created by: PyQt5 UI code generator 5.11.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets
import ctypes

class Ui_SettingWindow(object):
    def setupUi(self, SettingWindow):
        SettingWindow.setObjectName("SettingWindow")
        SettingWindow.resize(700, 800)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("Icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        SettingWindow.setWindowIcon(icon)
        myappid = 'mycompany.myproduct.subproduct.version'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        self.centralwidget = QtWidgets.QWidget(SettingWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(570, 718, 93, 28))
        self.pushButton.setObjectName("pushButton")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(32, 9, 81, 31))
        font = QtGui.QFont()
        font.setFamily("맑은 고딕")
        font.setPointSize(10)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.tableWidget = QtWidgets.QTableWidget(self.centralwidget)
        self.tableWidget.setGeometry(QtCore.QRect(30, 40, 631, 669))
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setColumnWidth(0, 120)
        self.tableWidget.setColumnWidth(1, 350)
        self.tableWidget.setColumnWidth(2, 120)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, item)
        SettingWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(SettingWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 700, 26))
        self.menubar.setObjectName("menubar")
        SettingWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(SettingWindow)
        self.statusbar.setObjectName("statusbar")
        SettingWindow.setStatusBar(self.statusbar)

        self.retranslateUi(SettingWindow)
        self.pushButton.clicked.connect(self.Setting_slot1)
        QtCore.QMetaObject.connectSlotsByName(SettingWindow)

        row_number = 0
        self.tableWidget.insertRow(row_number)
        self.tableWidget.setItem(row_number, 0, QtWidgets.QTableWidgetItem("1"))
        self.tableWidget.setItem(row_number, 1, QtWidgets.QTableWidgetItem("취약한 함수 사용"))
        self.tableWidget.setItem(row_number, 2, QtWidgets.QTableWidgetItem("O"))

    def Setting_slot1(self):
        pass

    def retranslateUi(self, SettingWindow):
        _translate = QtCore.QCoreApplication.translate
        SettingWindow.setWindowTitle(_translate("SettingWindow", "SAST [설정]"))
        self.pushButton.setText(_translate("SettingWindow", "저장"))
        self.label.setText(_translate("SettingWindow", "설정"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("SettingWindow", "번호"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("SettingWindow", "점검항목"))
        item = self.tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("SettingWindow", "활성화 여부"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    SettingWindow = QtWidgets.QMainWindow()
    ui = Ui_SettingWindow()
    ui.setupUi(SettingWindow)
    SettingWindow.show()
    sys.exit(app.exec_())

