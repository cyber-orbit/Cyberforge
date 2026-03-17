"""
CyberForge Tab Widget
Custom tab widget with new-tab button and drag support.
(Thin wrapper — main logic lives in core/tab_manager.py)
"""

from PyQt5.QtWidgets import QTabBar, QTabWidget, QToolButton, QSizePolicy
from PyQt5.QtCore import Qt, pyqtSignal, QSize
from PyQt5.QtGui import QIcon


class CyberTabBar(QTabBar):
    """
    Custom tab bar with cybersecurity styling.
    Shows a '+' new-tab button on the right side.
    """
    new_tab_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setExpanding(False)
        self.setMovable(True)
        self.setDrawBase(False)
        self.setElideMode(Qt.ElideRight)

    def mouseDoubleClickEvent(self, event):
        """Double-click on empty area → new tab."""
        if self.tabAt(event.pos()) == -1:
            self.new_tab_requested.emit()
        super().mouseDoubleClickEvent(event)
