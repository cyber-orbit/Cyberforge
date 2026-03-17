#!/bin/bash
# ============================================================
# CyberForge Browser - Automated Installer
# Supports: Ubuntu, Debian, Kali Linux, MX Linux
# ============================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

banner() {
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║     ⚡ CyberForge Browser Installer  ║"
    echo "  ║          Version 1.0.0               ║"
    echo "  ╚══════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }
log_step()    { echo -e "${CYAN}[→]${NC} $1"; }

banner

# ── Check OS ────────────────────────────────────────────────
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    log_error "This installer is for Linux only."
    exit 1
fi

# ── Check Python ────────────────────────────────────────────
log_step "Checking Python 3..."
if ! command -v python3 &>/dev/null; then
    log_error "Python 3 is not installed. Installing..."
    sudo apt-get install -y python3
fi
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
log_info "Python $PYTHON_VERSION found"

# ── System packages ─────────────────────────────────────────
log_step "Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y \
    python3-pip \
    python3-venv \
    python3-pyqt5 \
    python3-pyqt5.qtwebengine \
    python3-pyqt5.qtsvg \
    libqt5webengine5 \
    2>/dev/null || log_warn "Some system packages may not be available"

log_info "System dependencies installed"

# ── Virtual environment ──────────────────────────────────────
log_step "Creating virtual environment..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d "venv" ]; then
    python3 -m venv venv --system-site-packages
    log_info "Virtual environment created"
else
    log_warn "Virtual environment already exists, skipping"
fi

# Activate
source venv/bin/activate

# ── Python packages ──────────────────────────────────────────
log_step "Installing Python packages..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
log_info "Python packages installed"

# ── Generate icon ────────────────────────────────────────────
log_step "Generating app icon..."
python assets/icons/generate_icon.py 2>/dev/null || log_warn "Icon generation skipped"

# ── Create launcher script ───────────────────────────────────
log_step "Creating launcher script..."
cat > run_cyberforge.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source venv/bin/activate 2>/dev/null || true
python cyberforge.py "$@"
EOF
chmod +x run_cyberforge.sh
log_info "Launcher created: ./run_cyberforge.sh"

# ── Desktop entry (optional) ─────────────────────────────────
if [ -d "$HOME/.local/share/applications" ]; then
    log_step "Creating desktop entry..."
    cat > "$HOME/.local/share/applications/cyberforge.desktop" << EOF
[Desktop Entry]
Version=1.0
Name=CyberForge Browser
Comment=Cybersecurity-focused browser with investigation tools
Exec=$SCRIPT_DIR/run_cyberforge.sh
Icon=$SCRIPT_DIR/assets/icons/logo.png
Terminal=false
Type=Application
Categories=Network;Security;
Keywords=browser;security;hacking;recon;
EOF
    log_info "Desktop entry created"
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  ${GREEN}✓ CyberForge Browser installed!${NC}          ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  To run:   ${GREEN}./run_cyberforge.sh${NC}"
echo -e "  Or:       ${GREEN}source venv/bin/activate && python cyberforge.py${NC}"
echo ""
echo -e "  Press ${YELLOW}F12${NC} inside the browser to open the Security Panel."
echo ""
