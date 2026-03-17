"""
CyberForge Security Panel
The F12 investigation side panel with all security tools.
"""

import threading
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit,
    QScrollArea, QFrame, QProgressBar, QSizePolicy,
    QComboBox, QGroupBox,
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QColor

from security.phishing_detector import PhishingDetector
from security.url_analyzer import URLAnalyzer
from security.data_leak_scanner import DataLeakScanner
from recon.dns_lookup import DNSLookup
from recon.whois_lookup import WhoisLookup
from recon.subdomain_lookup import SubdomainLookup


# ── Worker threads for non-blocking operations ────────────────────────────────

class WorkerThread(QThread):
    result_ready = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.result_ready.emit(str(result))
        except Exception as e:
            self.error_occurred.emit(str(e))


# ── Panel widgets ─────────────────────────────────────────────────────────────

PANEL_STYLE = """
    QWidget {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 12px;
    }
    QTabWidget::pane { border: 1px solid #30363d; }
    QTabBar::tab {
        background: #161b22; color: #8b949e;
        padding: 6px 12px; border: none;
    }
    QTabBar::tab:selected { background: #1f2937; color: #00ff88; border-bottom: 2px solid #00ff88; }
    QTabBar::tab:hover { background: #1f2937; }
    QLineEdit {
        background: #161b22; color: #c9d1d9;
        border: 1px solid #30363d; border-radius: 4px;
        padding: 5px 8px;
    }
    QLineEdit:focus { border-color: #00ff88; }
    QPushButton {
        background: #21262d; color: #c9d1d9;
        border: 1px solid #30363d; border-radius: 4px;
        padding: 5px 12px;
    }
    QPushButton:hover { background: #30363d; color: #00ff88; border-color: #00ff88; }
    QPushButton:pressed { background: #00ff88; color: #0d1117; }
    QTextEdit {
        background: #0d1117; color: #c9d1d9;
        border: 1px solid #21262d; border-radius: 4px;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 11px;
    }
    QLabel { color: #c9d1d9; }
    QGroupBox {
        border: 1px solid #30363d; border-radius: 4px;
        margin-top: 8px; padding-top: 8px; color: #8b949e;
    }
    QGroupBox::title { subcontrol-origin: margin; left: 8px; color: #00ff88; }
    QProgressBar {
        border: 1px solid #30363d; background: #161b22;
        height: 8px; text-align: center; border-radius: 4px;
    }
    QProgressBar::chunk { background: #00ff88; border-radius: 4px; }
    QScrollBar:vertical {
        background: #0d1117; width: 8px;
        border: none;
    }
    QScrollBar::handle:vertical { background: #30363d; border-radius: 4px; min-height: 20px; }
    QScrollBar::handle:vertical:hover { background: #00ff88; }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""


def make_output_box(height: int = 200) -> QTextEdit:
    box = QTextEdit()
    box.setReadOnly(True)
    box.setMinimumHeight(height)
    return box


def make_header(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet("color: #00ff88; font-size: 13px; font-weight: bold; padding: 4px 0;")
    return lbl


def make_input_row(*widgets) -> QHBoxLayout:
    row = QHBoxLayout()
    row.setSpacing(6)
    for w in widgets:
        row.addWidget(w)
    return row


# ── Individual tabs ───────────────────────────────────────────────────────────

class PhishingTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.detector = PhishingDetector()
        self.analyzer = URLAnalyzer()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(make_header("🔍 Phishing & URL Analysis"))

        row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL to analyze...")
        btn = QPushButton("Analyze")
        btn.clicked.connect(self.run_analysis)
        self.url_input.returnPressed.connect(self.run_analysis)
        row.addWidget(self.url_input)
        row.addWidget(btn)
        layout.addLayout(row)

        # Risk indicator
        risk_row = QHBoxLayout()
        risk_row.addWidget(QLabel("Risk:"))
        self.risk_label = QLabel("—")
        self.risk_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        risk_row.addWidget(self.risk_label)
        risk_row.addStretch()
        self.score_label = QLabel("Score: —")
        risk_row.addWidget(self.score_label)
        layout.addLayout(risk_row)

        self.risk_bar = QProgressBar()
        self.risk_bar.setRange(0, 100)
        self.risk_bar.setValue(0)
        layout.addWidget(self.risk_bar)

        layout.addWidget(QLabel("Analysis Results:"))
        self.output = make_output_box(150)
        layout.addWidget(self.output)

        layout.addWidget(QLabel("URL Structure:"))
        self.url_output = make_output_box(120)
        layout.addWidget(self.url_output)

        layout.addStretch()

    def run_analysis(self):
        url = self.url_input.text().strip()
        if not url:
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        risk, score, reasons = self.detector.analyze(url)
        color = self.detector.get_color(risk)

        self.risk_label.setText(risk.upper())
        self.risk_label.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 13px;")
        self.score_label.setText(f"Score: {score}/100")

        self.risk_bar.setValue(score)
        if score >= 50:
            self.risk_bar.setStyleSheet("QProgressBar::chunk { background: #ff4444; }")
        elif score >= 20:
            self.risk_bar.setStyleSheet("QProgressBar::chunk { background: #ffcc00; }")
        else:
            self.risk_bar.setStyleSheet("QProgressBar::chunk { background: #00ff88; }")

        self.output.setPlainText("\n".join(reasons) if reasons else "No threats detected.")

        analysis = self.analyzer.analyze(url)
        self.url_output.setPlainText(self.analyzer.format_report(analysis))

    def analyze_url(self, url: str):
        self.url_input.setText(url)
        self.run_analysis()


class DataLeakTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = DataLeakScanner()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(make_header("💾 Data Leak Scanner"))

        row = QHBoxLayout()
        self.btn_scan = QPushButton("🔍 Scan Current Page")
        self.btn_scan.clicked.connect(lambda: self.parent_panel().request_page_scan())
        row.addWidget(self.btn_scan)
        layout.addLayout(row)

        self.status_label = QLabel("Click 'Scan Current Page' to begin.")
        self.status_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        layout.addWidget(self.status_label)

        self.output = make_output_box(280)
        layout.addWidget(self.output)
        layout.addStretch()

    def parent_panel(self):
        # Walk up to SecurityPanel
        w = self.parent()
        while w and not isinstance(w, SecurityPanel):
            w = w.parent()
        return w

    def display_results(self, html: str):
        results = self.scanner.scan_with_metadata(html)
        report = self.scanner.format_report(results)
        self.output.setPlainText(report)
        count = sum(r["count"] for r in results)
        if count:
            self.status_label.setText(f"⚠ Found {count} potential leak(s)!")
            self.status_label.setStyleSheet("color: #ff4444;")
        else:
            self.status_label.setText("✅ No data leaks detected.")
            self.status_label.setStyleSheet("color: #00ff88;")


class ReconTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.dns = DNSLookup()
        self.whois = WhoisLookup()
        self._build_ui()
        self._worker = None

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(make_header("🌐 DNS & WHOIS Recon"))

        row = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        row.addWidget(self.domain_input)
        layout.addLayout(row)

        btn_row = QHBoxLayout()
        dns_btn = QPushButton("DNS Lookup")
        whois_btn = QPushButton("WHOIS")
        dns_btn.clicked.connect(self.run_dns)
        whois_btn.clicked.connect(self.run_whois)
        btn_row.addWidget(dns_btn)
        btn_row.addWidget(whois_btn)
        layout.addLayout(btn_row)

        self.status = QLabel("")
        self.status.setStyleSheet("color: #8b949e;")
        layout.addWidget(self.status)

        self.output = make_output_box(280)
        layout.addWidget(self.output)
        layout.addStretch()

    def run_dns(self):
        domain = self.domain_input.text().strip()
        if not domain:
            return
        self.status.setText("Running DNS lookup...")
        self.output.setPlainText("Please wait...")

        self._worker = WorkerThread(self._do_dns, domain)
        self._worker.result_ready.connect(self.output.setPlainText)
        self._worker.error_occurred.connect(lambda e: self.output.setPlainText(f"Error: {e}"))
        self._worker.finished.connect(lambda: self.status.setText("Done."))
        self._worker.start()

    def _do_dns(self, domain):
        result = self.dns.lookup(domain)
        return self.dns.format_report(result)

    def run_whois(self):
        domain = self.domain_input.text().strip()
        if not domain:
            return
        self.status.setText("Running WHOIS lookup...")
        self.output.setPlainText("Please wait...")

        self._worker = WorkerThread(self._do_whois, domain)
        self._worker.result_ready.connect(self.output.setPlainText)
        self._worker.error_occurred.connect(lambda e: self.output.setPlainText(f"Error: {e}"))
        self._worker.finished.connect(lambda: self.status.setText("Done."))
        self._worker.start()

    def _do_whois(self, domain):
        result = self.whois.lookup(domain)
        return self.whois.format_report(result)

    def set_domain(self, domain: str):
        self.domain_input.setText(domain)


class SubdomainTab(QWidget):
    progress_update = pyqtSignal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = SubdomainLookup()
        self._build_ui()
        self._worker = None

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(make_header("🗺 Subdomain Scanner"))

        row = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        scan_btn = QPushButton("Start Scan")
        scan_btn.clicked.connect(self.run_scan)
        row.addWidget(self.domain_input)
        row.addWidget(scan_btn)
        layout.addLayout(row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        layout.addWidget(self.progress)

        self.status = QLabel("Ready.")
        self.status.setStyleSheet("color: #8b949e;")
        layout.addWidget(self.status)

        self.output = make_output_box(250)
        layout.addWidget(self.output)
        layout.addStretch()

        self.progress_update.connect(self._update_progress)

    @pyqtSlot(int, int)
    def _update_progress(self, current, total):
        pct = int(current / total * 100)
        self.progress.setValue(pct)
        self.status.setText(f"Scanning... {current}/{total}")

    def run_scan(self):
        domain = self.domain_input.text().strip()
        if not domain:
            return

        self.status.setText("Starting scan...")
        self.progress.setValue(0)
        self.output.setPlainText("Scanning subdomains, please wait...")

        def on_progress(cur, tot):
            self.progress_update.emit(cur, tot)

        self._worker = WorkerThread(self._do_scan, domain, on_progress)
        self._worker.result_ready.connect(self.output.setPlainText)
        self._worker.error_occurred.connect(lambda e: self.output.setPlainText(f"Error: {e}"))
        self._worker.finished.connect(lambda: self.status.setText("Scan complete."))
        self._worker.start()

    def _do_scan(self, domain, progress_cb):
        result = self.scanner.scan(domain, progress_callback=progress_cb)
        return self.scanner.format_report(result)

    def set_domain(self, domain: str):
        self.domain_input.setText(domain)


# ── Main Security Panel ───────────────────────────────────────────────────────

class SecurityPanel(QWidget):
    """
    The main F12 security investigation side panel.
    Contains tabs for phishing, data leaks, DNS/WHOIS, and subdomain scanning.
    """

    page_scan_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(360)
        self.setMaximumWidth(520)
        self.setStyleSheet(PANEL_STYLE)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar
        header = QFrame()
        header.setFixedHeight(36)
        header.setStyleSheet("background: #161b22; border-bottom: 1px solid #30363d;")
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(10, 0, 10, 0)

        title = QLabel("⚡ CyberForge Security Panel")
        title.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 13px;")
        h_layout.addWidget(title)
        h_layout.addStretch()

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(24, 24)
        close_btn.setStyleSheet("""
            QPushButton { background: transparent; border: none; color: #8b949e; font-size: 14px; }
            QPushButton:hover { color: #ff4444; }
        """)
        close_btn.clicked.connect(self.hide)
        h_layout.addWidget(close_btn)
        layout.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.phishing_tab = PhishingTab(self)
        self.data_leak_tab = DataLeakTab(self)
        self.recon_tab = ReconTab(self)
        self.subdomain_tab = SubdomainTab(self)

        self.tabs.addTab(self.phishing_tab, "🔍 Phishing")
        self.tabs.addTab(self.data_leak_tab, "💾 Data Leaks")
        self.tabs.addTab(self.recon_tab, "🌐 DNS/WHOIS")
        self.tabs.addTab(self.subdomain_tab, "🗺 Subdomains")

        layout.addWidget(self.tabs)

    def request_page_scan(self):
        """Signal main window to provide page HTML for scanning."""
        self.page_scan_requested.emit()

    def update_url(self, url: str):
        """Called when browser navigates to a new URL."""
        self.phishing_tab.analyze_url(url)
        # Pre-fill domain fields
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc
            if domain.startswith("www."):
                domain = domain[4:]
            if domain:
                self.recon_tab.set_domain(domain)
                self.subdomain_tab.set_domain(domain)
        except Exception:
            pass

    def feed_page_html(self, html: str):
        """Feed page HTML to the data leak scanner."""
        self.data_leak_tab.display_results(html)
        self.tabs.setCurrentWidget(self.data_leak_tab)
