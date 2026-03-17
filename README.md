# ⚡ CyberForge Browser

<p align="center">
  <img src="assets/icons/logo.svg" width="80" alt="CyberForge Logo"/>
</p>

<p align="center">
  <b>A lightweight cybersecurity-focused browser with built-in investigation and security tools.</b><br/>
  Built with Python · PyQt5 · Qt WebEngine
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/PyQt5-5.15%2B-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux"/>
  <img src="https://img.shields.io/badge/License-MIT-purple?style=flat-square"/>
</p>

---
<img width="1363" height="731" alt="Screenshot From 2026-03-17 16-55-54" src="https://github.com/user-attachments/assets/7d6e491e-135c-4161-8c16-29f57adee90b" />

<img width="363" height="628" alt="Screenshot From 2026-03-17 16-56-26" src="https://github.com/user-attachments/assets/79d62575-8211-4d50-b882-5eb9ac63ce04" />
<img width="1364" height="741" alt="Screenshot From 2026-03-17 17-14-57" src="https://github.com/user-attachments/assets/84f7fd45-a22b-456e-af4a-795b76fe3a2c" />

## ✨ Features

### 🌐 Core Browser
- **Tabbed browsing** — multiple tabs with Ctrl+T / Ctrl+W
- **Full navigation** — back, forward, reload, address bar
- **Bookmarks** — save and manage with ☆ button or Ctrl+B
- **History** — browsing history with Ctrl+H
- **Download support** via Qt WebEngine
- **Dark cybersecurity theme** throughout

### 🔐 Security Features
- **Phishing Detection** — heuristic URL analysis (keywords, TLDs, structure, brand spoofing)
- **Color-coded security indicator** — 🟢 Safe / 🟡 Unknown / 🔴 Suspicious
- **Automatic security alerts** — popup warnings for suspicious URLs

### 💾 Data Leak Scanner
Scans webpage source for exposed sensitive data:
- Email addresses
- Phone numbers
- Credit card numbers
- API keys & tokens (AWS, GitHub, JWT)
- Passwords in source code
- Social Security Numbers
- IP addresses

### 🌍 Reconnaissance Tools (F12 Panel)
- **DNS Lookup** — A, AAAA, MX, NS, TXT, CNAME records
- **WHOIS Lookup** — registrar, creation/expiry dates, name servers
- **Subdomain Scanner** — concurrent DNS brute-force with 80+ common subdomains

### 📋 Report Export
- **JSON report** — full structured investigation data
- **Text report** — human-readable summary
- **Screenshot** — capture current page as PNG

---

## 🗂 Project Structure

```
cyberforge_browser/
│
├── cyberforge.py            ← Entry point
│
├── core/
│   ├── browser_engine.py    ← QWebEngineView wrapper
│   └── tab_manager.py       ← Multi-tab management
│
├── ui/
│   ├── main_window.py       ← Main application window
│   ├── toolbar.py           ← Navigation toolbar & address bar
│   ├── tab_widget.py        ← Custom tab bar
│   └── security_panel.py    ← F12 investigation side panel
│
├── security/
│   ├── phishing_detector.py ← Heuristic phishing analysis
│   ├── data_leak_scanner.py ← Regex-based data leak detection
│   └── url_analyzer.py      ← URL structure analysis
│
├── recon/
│   ├── dns_lookup.py        ← DNS record queries
│   ├── whois_lookup.py      ← WHOIS domain info
│   └── subdomain_lookup.py  ← Subdomain enumeration
│
├── report/
│   └── export_report.py     ← JSON/text/screenshot export
│
├── assets/
│   ├── icons/               ← App icons
│   └── themes/              ← QSS stylesheets
│
├── config/
│   └── settings.json        ← Persistent settings
│
└── requirements.txt
```

---

## ⚙️ Installation
## 👾 Quick Installation

```bash
git clone https://github.com/cyber-orbit/Cyberforge.git
cd Cyberforge
chmod +x install.sh
./install.sh
chmod +x run_cyberforge.sh
./run_cyberforge.sh
```

### Prerequisites

- **Python 3.8+**
- **Linux** (Kali Linux, MX Linux, Ubuntu recommended)
- **pip**

### Step 1 — Clone the repository

```bash
git clone https://github.com/cyber-orbit/Cyberforge.git
cd Cyberforge
```

### Step 2 — Install system dependencies

**Ubuntu / Debian / Kali Linux / MX Linux:**
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv \
    python3-pyqt5 python3-pyqt5.qtwebengine \
    python3-pyqt5.qtsvg libqt5webengine5 \
    chromium-driver
```

### Step 3 — Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 4 — Install Python dependencies

```bash
pip install -r requirements.txt
```

> **Tip for Kali Linux:** If PyQtWebEngine fails via pip, use the system package:
> ```bash
> sudo apt install python3-pyqt5.qtwebengine
> ```

### Step 5 — Generate the app icon (optional)

```bash
python assets/icons/generate_icon.py
```

---

## 🚀 Running CyberForge

```bash
python cyberforge.py
```

Or from inside the project directory:

```bash
cd cyberforge_browser
python cyberforge.py
```

---

## ⌨️ Keyboard Shortcuts

| Shortcut       | Action                    |
|----------------|---------------------------|
| `Ctrl+T`       | New tab                   |
| `Ctrl+W`       | Close current tab         |
| `Ctrl+L`       | Focus address bar         |
| `Ctrl+B`       | Open bookmarks            |
| `Ctrl+H`       | Open history              |
| `F5`           | Reload page               |
| `F12`          | Toggle Security Panel     |
| `Alt+Left`     | Go back                   |
| `Alt+Right`    | Go forward                |

---

## 🔐 Security Panel (F12)

Press **F12** or click **⚡** in the toolbar to open the Security Panel.

| Tab          | Description                                           |
|--------------|-------------------------------------------------------|
| 🔍 Phishing  | Analyze any URL for phishing risk with score (0-100)  |
| 💾 Data Leaks | Scan current page HTML for exposed sensitive data    |
| 🌐 DNS/WHOIS  | DNS record queries + WHOIS domain registration info  |
| 🗺 Subdomains | Concurrent subdomain brute-force scanner             |

---

## 📦 Exporting Reports

Go to **File menu** or the toolbar to export:

- **File → Export JSON Report** — full machine-readable investigation data
- **File → Export Text Report** — human-readable summary
- **File → Save Screenshot** — PNG screenshot of the current page

---

## 🛠 Troubleshooting

### "No module named 'PyQt5.QtWebEngineWidgets'"
```bash
sudo apt install python3-pyqt5.qtwebengine
# or
pip install PyQtWebEngine
```

### Browser shows blank page
```bash
# Set display if running headless or via SSH
export DISPLAY=:0
python cyberforge.py
```

### WHOIS / DNS very slow or timing out
- Ensure you have internet connectivity
- Try: `ping 8.8.8.8`
- DNS timeouts are set to 5 seconds per query; WHOIS to 10 seconds

### dnspython not found (limited DNS features)
```bash
pip install dnspython
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

---

## ⚠️ Disclaimer

CyberForge Browser is intended for **educational and authorized security research purposes only**.

- Only scan domains and systems you own or have explicit written permission to test
- The phishing detection is heuristic-based and not 100% accurate
- Do not use reconnaissance tools against unauthorized targets
- The authors assume no liability for misuse

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Credits

Built with:
- [PyQt5](https://riverbankcomputing.com/software/pyqt/) — GUI framework
- [Qt WebEngine](https://doc.qt.io/qt-5/qtwebengine-index.html) — Browser engine
- [dnspython](https://www.dnspython.org/) — DNS toolkit
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) — HTML parsing

---

<p align="center">Made with ⚡ by the Cyber-orbit</p>
