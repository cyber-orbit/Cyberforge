"""
CyberForge Export Report
Exports investigation results in JSON and text formats.
"""

import json
import os
import datetime
from typing import Dict, Any, Optional
from PyQt5.QtWidgets import QFileDialog, QWidget, QMessageBox
from PyQt5.QtGui import QPixmap


class ExportReport:
    """
    Handles exporting security investigation results.
    Supports JSON reports and screenshot exports.
    """

    def __init__(self, parent_widget: Optional[QWidget] = None):
        self.parent = parent_widget

    def build_report(self,
                     url: str,
                     phishing_result: Dict,
                     url_analysis: Dict,
                     data_leaks: list,
                     dns_result: Optional[Dict] = None,
                     whois_result: Optional[Dict] = None,
                     subdomains: Optional[Dict] = None) -> Dict[str, Any]:
        """Build a comprehensive JSON-serializable report."""
        return {
            "report_metadata": {
                "generated_at": datetime.datetime.now().isoformat(),
                "tool": "CyberForge Browser",
                "version": "1.0.0",
                "target_url": url,
            },
            "phishing_analysis": {
                "risk_level": phishing_result.get("risk_level", "unknown"),
                "score": phishing_result.get("score", 0),
                "reasons": phishing_result.get("reasons", []),
            },
            "url_analysis": url_analysis,
            "data_leaks": [
                {
                    "type": item.get("type"),
                    "severity": item.get("severity"),
                    "count": item.get("count"),
                    "samples": item.get("matches", [])[:3],
                }
                for item in data_leaks
            ],
            "dns_lookup": dns_result or {},
            "whois_lookup": {
                k: v for k, v in (whois_result or {}).items() if k != "raw"
            },
            "subdomain_scan": subdomains or {},
            "summary": {
                "total_data_leaks": sum(i.get("count", 0) for i in data_leaks),
                "data_leak_categories": len(data_leaks),
                "phishing_risk": phishing_result.get("risk_level", "unknown"),
                "subdomains_found": len((subdomains or {}).get("found", [])),
            }
        }

    def export_json(self, report: Dict, filepath: Optional[str] = None) -> str:
        """
        Export report as a JSON file.
        If filepath is None, opens a save dialog.
        Returns filepath on success, empty string on cancel/error.
        """
        if not filepath and self.parent:
            default_name = f"cyberforge_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath, _ = QFileDialog.getSaveFileName(
                self.parent,
                "Export JSON Report",
                os.path.expanduser(f"~/{default_name}"),
                "JSON Files (*.json);;All Files (*)",
            )

        if not filepath:
            return ""

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)

            if self.parent:
                QMessageBox.information(
                    self.parent,
                    "Export Successful",
                    f"Report saved to:\n{filepath}"
                )
            return filepath
        except Exception as e:
            if self.parent:
                QMessageBox.critical(self.parent, "Export Error", str(e))
            return ""

    def export_screenshot(self, pixmap: QPixmap, filepath: Optional[str] = None) -> str:
        """
        Save a QPixmap screenshot to file.
        Returns filepath on success.
        """
        if not filepath and self.parent:
            default_name = f"cyberforge_screenshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            filepath, _ = QFileDialog.getSaveFileName(
                self.parent,
                "Save Screenshot",
                os.path.expanduser(f"~/{default_name}"),
                "PNG Images (*.png);;JPEG Images (*.jpg);;All Files (*)",
            )

        if not filepath:
            return ""

        try:
            pixmap.save(filepath)
            if self.parent:
                QMessageBox.information(
                    self.parent,
                    "Screenshot Saved",
                    f"Screenshot saved to:\n{filepath}"
                )
            return filepath
        except Exception as e:
            if self.parent:
                QMessageBox.critical(self.parent, "Screenshot Error", str(e))
            return ""

    def export_text_report(self, report: Dict, filepath: Optional[str] = None) -> str:
        """Export a human-readable text version of the report."""
        if not filepath and self.parent:
            default_name = f"cyberforge_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath, _ = QFileDialog.getSaveFileName(
                self.parent,
                "Export Text Report",
                os.path.expanduser(f"~/{default_name}"),
                "Text Files (*.txt);;All Files (*)",
            )

        if not filepath:
            return ""

        try:
            lines = [
                "╔══════════════════════════════════════════╗",
                "║         CYBERFORGE BROWSER REPORT        ║",
                "╚══════════════════════════════════════════╝",
                "",
                f"Generated : {report['report_metadata']['generated_at']}",
                f"Target URL: {report['report_metadata']['target_url']}",
                "",
                "═══ PHISHING ANALYSIS ═══",
                f"Risk Level: {report['phishing_analysis']['risk_level'].upper()}",
                f"Score     : {report['phishing_analysis']['score']}/100",
            ]

            for reason in report['phishing_analysis']['reasons']:
                lines.append(f"  • {reason}")

            lines += ["", "═══ DATA LEAKS ═══"]
            leaks = report.get("data_leaks", [])
            if leaks:
                for leak in leaks:
                    lines.append(f"[{leak['severity'].upper()}] {leak['type']}: {leak['count']} found")
            else:
                lines.append("No data leaks detected.")

            lines += ["", "═══ SUMMARY ═══"]
            summary = report.get("summary", {})
            for k, v in summary.items():
                lines.append(f"  {k}: {v}")

            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))

            if self.parent:
                QMessageBox.information(
                    self.parent,
                    "Export Successful",
                    f"Text report saved to:\n{filepath}"
                )
            return filepath
        except Exception as e:
            if self.parent:
                QMessageBox.critical(self.parent, "Export Error", str(e))
            return ""
