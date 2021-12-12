import sys
from PyQt5.QtWidgets import QApplication
from gui.MainWindow import MainWindow


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main = MainWindow()
    main.show()
    sys.exit(app.exec())
    print(main.conn)