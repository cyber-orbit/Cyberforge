"""
CyberForge Tab Manager
Manages browser tabs and their lifecycle.
"""

from PyQt5.QtWidgets import QTabWidget, QWidget, QVBoxLayout, QTabBar
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QIcon
from core.browser_engine import BrowserEngine


class TabManager(QTabWidget):
    """
    Manages multiple browser tabs.
    Each tab contains a BrowserEngine instance.
    """

    url_changed = pyqtSignal(str, int)       # url, tab_index
    title_changed = pyqtSignal(str, int)     # title, tab_index
    load_finished = pyqtSignal(bool, int)    # success, tab_index
    tab_security_update = pyqtSignal(str, int)  # url, tab_index

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTabsClosable(True)
        self.setMovable(True)
        self.setDocumentMode(True)
        self.tabCloseRequested.connect(self.close_tab)
        self.currentChanged.connect(self._on_tab_changed)
        self._apply_style()

    def _apply_style(self):
        self.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: #0d1117;
            }
            QTabBar::tab {
                background: #161b22;
                color: #8b949e;
                padding: 8px 16px;
                border: none;
                border-bottom: 2px solid transparent;
                min-width: 100px;
                max-width: 200px;
            }
            QTabBar::tab:selected {
                background: #1f2937;
                color: #00ff88;
                border-bottom: 2px solid #00ff88;
            }
            QTabBar::tab:hover {
                background: #1f2937;
                color: #c9d1d9;
            }
            QTabBar::close-button {
                image: none;
                subcontrol-position: right;
            }
        """)

    def new_tab(self, url: str = "https://www.google.com") -> int:
        """Create a new browser tab and return its index."""
        browser = BrowserEngine()

        # Connect signals
        browser.url_changed_signal.connect(
            lambda u, idx=self.count(): self._handle_url_change(u, idx)
        )
        browser.title_changed_signal.connect(
            lambda t, idx=self.count(): self._handle_title_change(t, idx)
        )
        browser.load_finished_signal.connect(
            lambda ok, idx=self.count(): self._handle_load_finished(ok, idx)
        )

        index = self.addTab(browser, "New Tab")
        self.setCurrentIndex(index)
        browser.navigate(url)

        return index

    def _handle_url_change(self, url: str, index: int):
        """Recalculate actual tab index (tabs may have been reordered/closed)."""
        browser = self.sender()
        actual_index = self.indexOf(browser)
        if actual_index >= 0:
            self.url_changed.emit(url, actual_index)
            self.tab_security_update.emit(url, actual_index)

    def _handle_title_change(self, title: str, index: int):
        browser = self.sender()
        actual_index = self.indexOf(browser)
        if actual_index >= 0:
            short_title = title[:20] + "..." if len(title) > 20 else title
            self.setTabText(actual_index, short_title or "New Tab")
            self.title_changed.emit(title, actual_index)

    def _handle_load_finished(self, ok: bool, index: int):
        browser = self.sender()
        actual_index = self.indexOf(browser)
        if actual_index >= 0:
            self.load_finished.emit(ok, actual_index)

    def _on_tab_changed(self, index: int):
        if index >= 0:
            browser = self.current_browser()
            if browser:
                self.url_changed.emit(browser.url().toString(), index)

    def current_browser(self) -> BrowserEngine:
        """Return the BrowserEngine in the current tab."""
        return self.currentWidget()

    def get_browser_at(self, index: int) -> BrowserEngine:
        return self.widget(index)

    def close_tab(self, index: int):
        """Close a tab; keep at least one tab open."""
        if self.count() > 1:
            widget = self.widget(index)
            self.removeTab(index)
            if widget:
                widget.deleteLater()
        else:
            # Reset the last tab to home
            browser = self.current_browser()
            if browser:
                browser.navigate("https://www.google.com")

    def navigate_current(self, url: str):
        browser = self.current_browser()
        if browser:
            browser.navigate(url)

    def go_back(self):
        browser = self.current_browser()
        if browser and browser.history().canGoBack():
            browser.back()

    def go_forward(self):
        browser = self.current_browser()
        if browser and browser.history().canGoForward():
            browser.forward()

    def reload_current(self):
        browser = self.current_browser()
        if browser:
            browser.reload()

    def stop_loading(self):
        browser = self.current_browser()
        if browser:
            browser.stop()
