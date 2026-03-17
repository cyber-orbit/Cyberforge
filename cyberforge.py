#!/usr/bin/env python3
"""
CyberForge Browser - Main Entry Point
A lightweight cybersecurity-focused browser with built-in investigation tools.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from ui.main_window import MainWindow


def main():
    # Enable High DPI support
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("CyberForge Browser")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("CyberForge")

    # Set app icon if exists
    icon_path = os.path.join(os.path.dirname(__file__), "assets", "icons", "logo.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
