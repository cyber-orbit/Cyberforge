"""
CyberForge Main Window
The primary application window integrating all components.
"""

import os
import json
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QSplitter, QStatusBar, QLabel, QAction, QMenu,
    QMenuBar, QInputDialog, QMessageBox, QDialog,
    QListWidget, QDialogButtonBox, QListWidgetItem,
    QShortcut,
)
from PyQt5.QtCore import Qt, QUrl, QTimer, pyqtSlot
from PyQt5.QtGui import QKeySequence, QFont, QIcon

from core.tab_manager import TabManager
from ui.toolbar import NavigationToolbar
from ui.security_panel import SecurityPanel
from security.phishing_detector import PhishingDetector
from report.export_report import ExportReport

MAIN_STYLE = """
QMainWindow {
    background: #0d1117;
}
QMenuBar {
    background: #161b22;
    color: #c9d1d9;
    border-bottom: 1px solid #30363d;
    padding: 2px;
}
QMenuBar::item { padding: 4px 10px; }
QMenuBar::item:selected { background: #21262d; color: #00ff88; }
QMenu {
    background: #161b22; color: #c9d1d9;
    border: 1px solid #30363d;
}
QMenu::item:selected { background: #21262d; color: #00ff88; }
QStatusBar {
    background: #0d1117;
    color: #8b949e;
    border-top: 1px solid #21262d;
    font-size: 11px;
}
QSplitter::handle { background: #30363d; width: 1px; }
QSplitter::handle:hover { background: #00ff88; }
"""

CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "settings.json")

DEFAULT_CONFIG = {
    "home_url": "https://www.google.com",
    "bookmarks": [],
    "history": [],
    "max_history": 500,
    "auto_scan": True,
    "theme": "dark",
}


class BookmarkDialog(QDialog):
    """Simple dialog to view/manage bookmarks."""

    def __init__(self, bookmarks: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bookmarks")
        self.setMinimumSize(400, 300)
        self.setStyleSheet("""
            QDialog { background: #161b22; color: #c9d1d9; }
            QListWidget { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; }
            QListWidget::item:selected { background: #21262d; color: #00ff88; }
            QPushButton { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; padding: 5px 12px; border-radius: 4px; }
            QPushButton:hover { background: #30363d; color: #00ff88; }
        """)
        self.selected_url = ""

        layout = QVBoxLayout(self)
        self.list_widget = QListWidget()
        for bm in bookmarks:
            item = QListWidgetItem(f"⭐ {bm.get('title', bm.get('url', ''))}")
            item.setData(Qt.UserRole, bm.get("url", ""))
            self.list_widget.addItem(item)
        self.list_widget.itemDoubleClicked.connect(self._open_selected)
        layout.addWidget(self.list_widget)

        buttons = QDialogButtonBox(QDialogButtonBox.Open | QDialogButtonBox.Close)
        buttons.accepted.connect(self._open_selected)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _open_selected(self):
        items = self.list_widget.selectedItems()
        if items:
            self.selected_url = items[0].data(Qt.UserRole)
            self.accept()


class MainWindow(QMainWindow):
    """
    CyberForge Browser main application window.
    Integrates tabbed browsing, navigation toolbar, and security panel.
    """

    def __init__(self):
        super().__init__()
        self.config = self._load_config()
        self.phishing_detector = PhishingDetector()
        self.exporter = ExportReport(self)
        self._current_scan_results = []

        self._setup_window()
        self._build_ui()
        self._connect_signals()
        self._setup_shortcuts()
        self._setup_menu()

        # Open initial tab
        self.tab_manager.new_tab(self.config.get("home_url", "https://www.google.com"))

    def _setup_window(self):
        self.setWindowTitle("CyberForge Browser")
        self.setMinimumSize(1024, 700)
        self.resize(1280, 800)
        self.setStyleSheet(MAIN_STYLE)

    def _build_ui(self):
        # ── Central widget ────────────────────────────────────────────
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Toolbar ───────────────────────────────────────────────────
        self.toolbar = NavigationToolbar(self)
        self.addToolBar(self.toolbar)

        # ── Splitter: browser | security panel ───────────────────────
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setHandleWidth(1)

        # Tab manager (browser area)
        self.tab_manager = TabManager()
        self.splitter.addWidget(self.tab_manager)

        # Security panel (hidden by default)
        self.security_panel = SecurityPanel()
        self.security_panel.hide()
        self.splitter.addWidget(self.security_panel)

        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 1)

        main_layout.addWidget(self.splitter)

        # ── Status bar ────────────────────────────────────────────────
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.status_url = QLabel("")
        self.status_security = QLabel("⚡ CyberForge")
        self.status_security.setStyleSheet("color: #00ff88; font-weight: bold;")
        self.status_bar.addWidget(self.status_url, 1)
        self.status_bar.addPermanentWidget(self.status_security)

    def _connect_signals(self):
        # Toolbar ↔ browser
        self.toolbar.navigate_requested.connect(self.tab_manager.navigate_current)
        self.toolbar.new_tab_requested.connect(lambda: self.tab_manager.new_tab())
        self.toolbar.back_requested.connect(self.tab_manager.go_back)
        self.toolbar.forward_requested.connect(self.tab_manager.go_forward)
        self.toolbar.reload_requested.connect(self.tab_manager.reload_current)
        self.toolbar.bookmark_requested.connect(self._add_bookmark)
        self.toolbar.security_panel_toggle.connect(self._toggle_security_panel)

        # Tab manager → toolbar / security
        self.tab_manager.url_changed.connect(self._on_url_changed)
        self.tab_manager.title_changed.connect(self._on_title_changed)
        self.tab_manager.load_finished.connect(self._on_load_finished)
        self.tab_manager.tab_security_update.connect(self._check_security)

        # Security panel
        self.security_panel.page_scan_requested.connect(self._do_page_scan)

    def _setup_shortcuts(self):
        # F12 → toggle security panel
        QShortcut(QKeySequence("F12"), self).activated.connect(self._toggle_security_panel)
        # Ctrl+T → new tab
        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(lambda: self.tab_manager.new_tab())
        # Ctrl+W → close tab
        QShortcut(QKeySequence("Ctrl+W"), self).activated.connect(
            lambda: self.tab_manager.close_tab(self.tab_manager.currentIndex())
        )
        # F5 → reload
        QShortcut(QKeySequence("F5"), self).activated.connect(self.tab_manager.reload_current)
        # Alt+Left → back
        QShortcut(QKeySequence("Alt+Left"), self).activated.connect(self.tab_manager.go_back)
        # Alt+Right → forward
        QShortcut(QKeySequence("Alt+Right"), self).activated.connect(self.tab_manager.go_forward)
        # Ctrl+L → focus address bar
        QShortcut(QKeySequence("Ctrl+L"), self).activated.connect(self.toolbar.url_bar.setFocus)
        # Ctrl+B → bookmarks
        QShortcut(QKeySequence("Ctrl+B"), self).activated.connect(self._show_bookmarks)
        # Ctrl+H → history
        QShortcut(QKeySequence("Ctrl+H"), self).activated.connect(self._show_history)

    def _setup_menu(self):
        menubar = self.menuBar()

        # ── File ──────────────────────────────────────────────────────
        file_menu = menubar.addMenu("File")
        file_menu.addAction("New Tab\tCtrl+T", lambda: self.tab_manager.new_tab())
        file_menu.addAction("Close Tab\tCtrl+W",
                            lambda: self.tab_manager.close_tab(self.tab_manager.currentIndex()))
        file_menu.addSeparator()
        file_menu.addAction("Export JSON Report", self._export_json)
        file_menu.addAction("Export Text Report", self._export_text)
        file_menu.addAction("Save Screenshot", self._save_screenshot)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        # ── View ──────────────────────────────────────────────────────
        view_menu = menubar.addMenu("View")
        view_menu.addAction("Toggle Security Panel\tF12", self._toggle_security_panel)
        view_menu.addAction("Bookmarks\tCtrl+B", self._show_bookmarks)
        view_menu.addAction("History\tCtrl+H", self._show_history)

        # ── Tools ─────────────────────────────────────────────────────
        tools_menu = menubar.addMenu("Tools")
        tools_menu.addAction("Scan Page for Data Leaks", self._do_page_scan_and_show)
        tools_menu.addAction("Analyze Current URL", self._analyze_current_url)

        # ── Help ──────────────────────────────────────────────────────
        help_menu = menubar.addMenu("Help")
        help_menu.addAction("About CyberForge", self._show_about)

    # ── Slot handlers ──────────────────────────────────────────────────────────

    @pyqtSlot(str, int)
    def _on_url_changed(self, url: str, index: int):
        if index == self.tab_manager.currentIndex():
            self.toolbar.set_url(url)
            self.status_url.setText(url[:80])
            self._add_to_history(url)

    @pyqtSlot(str, int)
    def _on_title_changed(self, title: str, index: int):
        if index == self.tab_manager.currentIndex():
            self.setWindowTitle(f"{title} — CyberForge Browser")

    @pyqtSlot(bool, int)
    def _on_load_finished(self, ok: bool, index: int):
        if index == self.tab_manager.currentIndex():
            self.toolbar.set_loading(False)
            if not ok:
                self.status_bar.showMessage("Page load error.", 3000)

    @pyqtSlot(str, int)
    def _check_security(self, url: str, index: int):
        if index != self.tab_manager.currentIndex():
            return
        if not url or url.startswith("about:"):
            self.toolbar.set_security_level("unknown")
            return

        risk, score, reasons = self.phishing_detector.analyze(url)
        self.toolbar.set_security_level(risk)

        if risk == "suspicious":
            msg = "\n".join(reasons[:3])
            QMessageBox.warning(
                self,
                "⚠ Security Warning — CyberForge",
                f"Potential phishing or malicious site detected!\n\n{msg}\n\nURL: {url[:80]}"
            )

        # Auto-update security panel if open
        if self.security_panel.isVisible():
            self.security_panel.update_url(url)

    def _toggle_security_panel(self):
        if self.security_panel.isVisible():
            self.security_panel.hide()
        else:
            self.security_panel.show()
            # Auto-analyze current URL
            browser = self.tab_manager.current_browser()
            if browser:
                self.security_panel.update_url(browser.url().toString())

    def _do_page_scan(self):
        """Fetch page HTML and send to security panel."""
        browser = self.tab_manager.current_browser()
        if browser:
            browser.get_page_html(self.security_panel.feed_page_html)

    def _do_page_scan_and_show(self):
        if not self.security_panel.isVisible():
            self.security_panel.show()
        self._do_page_scan()

    def _analyze_current_url(self):
        browser = self.tab_manager.current_browser()
        if browser:
            if not self.security_panel.isVisible():
                self.security_panel.show()
            self.security_panel.update_url(browser.url().toString())
            self.security_panel.tabs.setCurrentIndex(0)  # phishing tab

    def _add_bookmark(self, url: str):
        title, ok = QInputDialog.getText(
            self, "Add Bookmark", "Bookmark name:", text=url
        )
        if ok and url:
            self.config.setdefault("bookmarks", []).append({"title": title or url, "url": url})
            self._save_config()
            self.status_bar.showMessage(f"Bookmarked: {url[:60]}", 3000)

    def _show_bookmarks(self):
        bookmarks = self.config.get("bookmarks", [])
        if not bookmarks:
            QMessageBox.information(self, "Bookmarks", "No bookmarks saved yet.\n\nUse ☆ to bookmark pages.")
            return
        dlg = BookmarkDialog(bookmarks, self)
        if dlg.exec_() == QDialog.Accepted and dlg.selected_url:
            self.tab_manager.navigate_current(dlg.selected_url)

    def _show_history(self):
        history = self.config.get("history", [])
        if not history:
            QMessageBox.information(self, "History", "No browsing history yet.")
            return
        items = list(reversed(history[-100:]))
        item, ok = QInputDialog.getItem(self, "Browsing History",
                                        "Select URL to navigate:", items, 0, False)
        if ok and item:
            self.tab_manager.navigate_current(item)

    def _add_to_history(self, url: str):
        if not url or url.startswith("about:"):
            return
        history = self.config.setdefault("history", [])
        if not history or history[-1] != url:
            history.append(url)
            max_h = self.config.get("max_history", 500)
            if len(history) > max_h:
                self.config["history"] = history[-max_h:]
            self._save_config()

    def _export_json(self):
        browser = self.tab_manager.current_browser()
        url = browser.url().toString() if browser else ""
        risk, score, reasons = self.phishing_detector.analyze(url)
        report = self.exporter.build_report(
            url=url,
            phishing_result={"risk_level": risk, "score": score, "reasons": reasons},
            url_analysis={},
            data_leaks=[],
        )
        self.exporter.export_json(report)

    def _export_text(self):
        browser = self.tab_manager.current_browser()
        url = browser.url().toString() if browser else ""
        risk, score, reasons = self.phishing_detector.analyze(url)
        report = self.exporter.build_report(
            url=url,
            phishing_result={"risk_level": risk, "score": score, "reasons": reasons},
            url_analysis={},
            data_leaks=[],
        )
        self.exporter.export_text_report(report)

    def _save_screenshot(self):
        browser = self.tab_manager.current_browser()
        if browser:
            browser.take_screenshot(lambda pixmap: self.exporter.export_screenshot(pixmap))

    def _show_about(self):
        QMessageBox.about(
            self,
            "About CyberForge Browser",
            "<h2 style='color:#00ff88'>⚡ CyberForge Browser</h2>"
            "<p><b>Version 1.0.0</b></p>"
            "<p>A lightweight cybersecurity-focused browser with built-in "
            "investigation tools for security professionals.</p>"
            "<hr>"
            "<p><b>Features:</b><br>"
            "• Phishing detection &amp; URL analysis<br>"
            "• Data leak scanner<br>"
            "• DNS &amp; WHOIS reconnaissance<br>"
            "• Subdomain enumeration<br>"
            "• Security report export</p>"
            "<p>Press <b>F12</b> to open the Security Panel.</p>"
        )

    # ── Config I/O ─────────────────────────────────────────────────────────────

    def _load_config(self) -> dict:
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    saved = json.load(f)
                    config = {**DEFAULT_CONFIG, **saved}
                    return config
        except Exception:
            pass
        return dict(DEFAULT_CONFIG)

    def _save_config(self):
        try:
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.config, f, indent=2)
        except Exception:
            pass

    def closeEvent(self, event):
        self._save_config()
        event.accept()
