"""
CyberForge Icon Generator
Creates a simple SVG/PNG logo programmatically.
Run once: python assets/icons/generate_icon.py
"""

import os

SVG_ICON = """<?xml version="1.0" encoding="UTF-8"?>
<svg width="64" height="64" viewBox="0 0 64 64"
     xmlns="http://www.w3.org/2000/svg">
  <!-- Background -->
  <rect width="64" height="64" rx="12" fill="#0d1117"/>
  <!-- Outer hex ring -->
  <polygon points="32,4 56,18 56,46 32,60 8,46 8,18"
           fill="none" stroke="#00ff88" stroke-width="2.5" opacity="0.8"/>
  <!-- Inner hex -->
  <polygon points="32,14 48,23 48,41 32,50 16,41 16,23"
           fill="none" stroke="#00ccff" stroke-width="1.5" opacity="0.5"/>
  <!-- Lightning bolt -->
  <path d="M36,12 L24,34 L31,34 L28,52 L40,30 L33,30 Z"
        fill="#00ff88" stroke="#00ff88" stroke-width="0.5"
        stroke-linejoin="round"/>
</svg>
"""

def generate():
    icon_dir = os.path.dirname(os.path.abspath(__file__))
    svg_path = os.path.join(icon_dir, "logo.svg")

    with open(svg_path, "w") as f:
        f.write(SVG_ICON)
    print(f"SVG icon saved: {svg_path}")

    # Try to convert to PNG using PyQt5 if available
    try:
        import sys
        sys.path.insert(0, os.path.join(icon_dir, "..", ".."))
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtSvg import QSvgRenderer
        from PyQt5.QtGui import QPixmap, QPainter
        from PyQt5.QtCore import QSize, Qt

        app = QApplication.instance() or QApplication(sys.argv)
        renderer = QSvgRenderer(svg_path)
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        renderer.render(painter)
        painter.end()
        png_path = os.path.join(icon_dir, "logo.png")
        pixmap.save(png_path, "PNG")
        print(f"PNG icon saved: {png_path}")
    except Exception as e:
        print(f"Note: PNG generation skipped ({e}). SVG icon created.")


if __name__ == "__main__":
    generate()
