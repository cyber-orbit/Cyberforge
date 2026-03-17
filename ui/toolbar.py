"""
CyberForge Toolbar
Navigation toolbar with address bar and security indicator.
"""

from PyQt5.QtWidgets import (
    QToolBar, QLineEdit, QAction, QLabel,
    QWidget, QHBoxLayout, QSizePolicy, QMenu,
)
from PyQt5.QtCore import pyqtSignal, Qt, QSize
from PyQt5.QtGui import QFont, QIcon

TOOLBAR_STYLE = """
QToolBar {
    background: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 4px 8px;
    spacing: 4px;
}
QToolButton {
    background: transparent;
    border: none;
    color: #c9d1d9;
    padding: 4px;
    border-radius: 4px;
    font-size: 16px;
    min-width: 28px;
    min-height: 28px;
}
QToolButton:hover { background: #21262d; color: #00ff88; }
QToolButton:pressed { background: #30363d; }
QToolButton:disabled { color: #484f58; }
QLineEdit {
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 16px;
    padding: 5px 14px;
    font-size: 13px;
    selection-background-color: #00ff8833;
}
QLineEdit:focus { border-color: #00ff88; background: #1f2937; }
QLabel { color: #c9d1d9; }
"""

SECURITY_INDICATOR_STYLES = {
    "safe":       "background: #00ff88; border-radius: 8px; min-width:16px; min-height:16px; max-width:16px; max-height:16px;",
    "unknown":    "background: #ffcc00; border-radius: 8px; min-width:16px; min-height:16px; max-width:16px; max-height:16px;",
    "suspicious": "background: #ff4444; border-radius: 8px; min-width:16px; min-height:16px; max-width:16px; max-height:16px;",
}


class NavigationToolbar(QToolBar):
    """
    Top navigation toolbar with back/forward/reload, address bar,
    and security color indicator.
    """

    navigate_requested = pyqtSignal(str)
    new_tab_requested = pyqtSignal()
    back_requested = pyqtSignal()
    forward_requested = pyqtSignal()
    reload_requested = pyqtSignal()
    bookmark_requested = pyqtSignal(str)
    security_panel_toggle = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMovable(False)
        self.setIconSize(QSize(20, 20))
        self.setStyleSheet(TOOLBAR_STYLE)
        self._build_toolbar()

    def _build_toolbar(self):
        # ── Navigation buttons ──────────────────────────────────────
        self.back_action = QAction("◀", self)
        self.back_action.setToolTip("Go Back")
        self.back_action.triggered.connect(self.back_requested.emit)
        self.addAction(self.back_action)

        self.forward_action = QAction("▶", self)
        self.forward_action.setToolTip("Go Forward")
        self.forward_action.triggered.connect(self.forward_requested.emit)
        self.addAction(self.forward_action)

        self.reload_action = QAction("↻", self)
        self.reload_action.setToolTip("Reload Page (F5)")
        self.reload_action.triggered.connect(self.reload_requested.emit)
        self.addAction(self.reload_action)

        self.addSeparator()

        # ── Security indicator dot ───────────────────────────────────
        self.security_dot = QLabel()
        self.security_dot.setFixedSize(16, 16)
        self.security_dot.setToolTip("Security Status")
        self.security_dot.setStyleSheet(SECURITY_INDICATOR_STYLES["unknown"])
        self.addWidget(self.security_dot)

        # ── Address bar ──────────────────────────────────────────────
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Enter URL or search...")
        self.url_bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.url_bar.returnPressed.connect(self._on_navigate)
        self.url_bar.setMinimumHeight(32)
        self.addWidget(self.url_bar)

        # ── Bookmark button ──────────────────────────────────────────
        self.bookmark_action = QAction("☆", self)
        self.bookmark_action.setToolTip("Bookmark this page")
        self.bookmark_action.triggered.connect(
            lambda: self.bookmark_requested.emit(self.url_bar.text())
        )
        self.addAction(self.bookmark_action)

        self.addSeparator()

        # ── New tab ──────────────────────────────────────────────────
        new_tab_action = QAction("+", self)
        new_tab_action.setToolTip("New Tab")
        new_tab_action.triggered.connect(self.new_tab_requested.emit)
        self.addAction(new_tab_action)

        # ── Security Panel toggle ────────────────────────────────────
        self.panel_action = QAction("⚡", self)
        self.panel_action.setToolTip("Security Panel (F12)")
        self.panel_action.triggered.connect(self.security_panel_toggle.emit)
        self.addAction(self.panel_action)

    def _on_navigate(self):
        url = self.url_bar.text().strip()
        if url:
            self.navigate_requested.emit(url)

    def set_url(self, url: str):
        """Update address bar text."""
        if not self.url_bar.hasFocus():
            self.url_bar.setText(url)

    def set_security_level(self, level: str):
        """Update the security indicator dot color."""
        style = SECURITY_INDICATOR_STYLES.get(level, SECURITY_INDICATOR_STYLES["unknown"])
        self.security_dot.setStyleSheet(style)
        tips = {
            "safe": "✅ Safe — No threats detected",
            "unknown": "⚠ Unknown — Could not verify safety",
            "suspicious": "🔴 Suspicious — Potential threat detected!",
        }
        self.security_dot.setToolTip(tips.get(level, "Unknown"))

    def set_loading(self, loading: bool):
        """Toggle reload/stop icon."""
        if loading:
            self.reload_action.setText("✕")
            self.reload_action.setToolTip("Stop Loading")
        else:
            self.reload_action.setText("↻")
            self.reload_action.setToolTip("Reload Page")
