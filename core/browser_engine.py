"""
CyberForge Browser Engine
Wraps QWebEngineView with security features.
"""

from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineSettings, QWebEnginePage
from PyQt5.QtCore import QUrl, pyqtSignal, QObject
from PyQt5.QtWidgets import QWidget


class SecureWebPage(QWebEnginePage):
    """Custom web page with security overrides."""

    def __init__(self, parent=None):
        super().__init__(parent)

    def javaScriptConsoleMessage(self, level, message, line, source):
        # Suppress console noise; could log to security panel
        pass


class BrowserEngine(QWebEngineView):
    """
    Core browser engine with security integration.
    Emits signals for URL changes, page title, load status.
    """

    url_changed_signal = pyqtSignal(str)
    title_changed_signal = pyqtSignal(str)
    load_started_signal = pyqtSignal()
    load_finished_signal = pyqtSignal(bool)
    favicon_changed_signal = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)

        # Use secure custom page
        self.secure_page = SecureWebPage(self)
        self.setPage(self.secure_page)

        # Configure web settings
        self._configure_settings()

        # Connect internal signals
        self.urlChanged.connect(self._on_url_changed)
        self.titleChanged.connect(self._on_title_changed)
        self.loadStarted.connect(self._on_load_started)
        self.loadFinished.connect(self._on_load_finished)
        self.iconChanged.connect(self._on_favicon_changed)

    def _configure_settings(self):
        """Configure security-oriented browser settings."""
        settings = self.settings()
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, False)
        settings.setAttribute(QWebEngineSettings.AutoLoadImages, True)
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.XSSAuditingEnabled, True)
        settings.setAttribute(QWebEngineSettings.ScrollAnimatorEnabled, True)

    def _on_url_changed(self, qurl):
        self.url_changed_signal.emit(qurl.toString())

    def _on_title_changed(self, title):
        self.title_changed_signal.emit(title)

    def _on_load_started(self):
        self.load_started_signal.emit()

    def _on_load_finished(self, success):
        self.load_finished_signal.emit(success)

    def _on_favicon_changed(self, icon):
        self.favicon_changed_signal.emit(icon)

    def navigate(self, url: str):
        """Navigate to a URL, auto-adding https:// if needed."""
        if not url.startswith(("http://", "https://", "file://")):
            # Check if it looks like a search query
            if " " in url or "." not in url:
                url = f"https://www.google.com/search?q={url.replace(' ', '+')}"
            else:
                url = "https://" + url
        self.setUrl(QUrl(url))

    def get_page_html(self, callback):
        """Asynchronously retrieve current page HTML."""
        self.page().toHtml(callback)

    def take_screenshot(self, callback):
        """Capture screenshot of current page."""
        self.grab()
        pixmap = self.grab()
        callback(pixmap)
