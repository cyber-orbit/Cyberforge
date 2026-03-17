"""
CyberForge Data Leak Scanner
Scans webpage content for exposed sensitive data using regex patterns.
"""

import re
from typing import Dict, List, Tuple


# Regex patterns for sensitive data detection
PATTERNS = {
    "Email Addresses": {
        "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "severity": "medium",
        "icon": "📧",
    },
    "Phone Numbers": {
        "pattern": r"(\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}",
        "severity": "medium",
        "icon": "📞",
    },
    "Credit Card Numbers": {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": "critical",
        "icon": "💳",
    },
    "API Keys / Tokens": {
        "pattern": r"(?:api[_\-]?key|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)[\s:=\"']+([a-zA-Z0-9\-_]{20,})",
        "severity": "critical",
        "icon": "🔑",
    },
    "AWS Access Keys": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "icon": "☁",
    },
    "Private Keys (PEM)": {
        "pattern": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "severity": "critical",
        "icon": "🔐",
    },
    "Passwords in Source": {
        "pattern": r"(?:password|passwd|pwd)[\s]*[=:\"']+[\s]*['\"]?([^\s'\"&<>]{6,})",
        "severity": "high",
        "icon": "🔒",
    },
    "Social Security Numbers": {
        "pattern": r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        "severity": "critical",
        "icon": "🪪",
    },
    "IPv4 Addresses": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "severity": "low",
        "icon": "🌐",
    },
    "JWT Tokens": {
        "pattern": r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
        "severity": "high",
        "icon": "🎫",
    },
    "GitHub Tokens": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "icon": "🐙",
    },
    "Bitcoin Addresses": {
        "pattern": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "severity": "medium",
        "icon": "₿",
    },
}

SEVERITY_COLORS = {
    "critical": "#ff2244",
    "high": "#ff8800",
    "medium": "#ffcc00",
    "low": "#88ccff",
}


class DataLeakScanner:
    """
    Scans HTML content for exposed sensitive data patterns.
    """

    def __init__(self):
        self.patterns = PATTERNS

    def scan(self, html_content: str) -> Dict[str, List[str]]:
        """
        Scan HTML content for all sensitive data patterns.

        Returns dict: { pattern_name: [list of found matches] }
        """
        results = {}

        if not html_content:
            return results

        for name, config in self.patterns.items():
            try:
                matches = re.findall(config["pattern"], html_content, re.IGNORECASE)
                if matches:
                    # Deduplicate and limit
                    unique_matches = list(set(
                        m if isinstance(m, str) else m[0]
                        for m in matches
                    ))[:10]  # cap at 10 results per type
                    results[name] = unique_matches
            except re.error:
                pass

        return results

    def scan_with_metadata(self, html_content: str) -> List[Dict]:
        """
        Scan and return results with severity and icon metadata.
        """
        raw_results = self.scan(html_content)
        full_results = []

        for name, matches in raw_results.items():
            config = self.patterns.get(name, {})
            full_results.append({
                "type": name,
                "matches": matches,
                "count": len(matches),
                "severity": config.get("severity", "unknown"),
                "icon": config.get("icon", "⚠"),
                "color": SEVERITY_COLORS.get(config.get("severity", "unknown"), "#ffffff"),
            })

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        full_results.sort(key=lambda x: severity_order.get(x["severity"], 99))

        return full_results

    def format_report(self, results: List[Dict]) -> str:
        """Format scan results into a readable report string."""
        if not results:
            return "✅ No sensitive data detected on this page."

        lines = ["═══ Data Leak Scan Results ═══", ""]
        total = sum(r["count"] for r in results)
        lines.append(f"⚠ Found {total} potential data exposure(s) in {len(results)} category(ies)")
        lines.append("")

        for item in results:
            lines.append(f"{item['icon']} {item['type']} [{item['severity'].upper()}]")
            lines.append(f"   Found: {item['count']} instance(s)")
            for match in item['matches'][:3]:  # Show max 3 samples
                # Partially mask sensitive data in display
                masked = self._mask_sensitive(match, item['type'])
                lines.append(f"   • {masked}")
            if item['count'] > 3:
                lines.append(f"   ... and {item['count'] - 3} more")
            lines.append("")

        return "\n".join(lines)

    def _mask_sensitive(self, value: str, data_type: str) -> str:
        """Partially mask sensitive values for display."""
        if not value:
            return "[empty]"
        
        high_sensitivity = {"Credit Card Numbers", "Social Security Numbers",
                           "Passwords in Source", "Private Keys (PEM)", "AWS Access Keys"}
        
        if data_type in high_sensitivity:
            if len(value) > 6:
                return value[:3] + "*" * (len(value) - 6) + value[-3:]
            return "***"
        
        # For emails, mask the local part
        if data_type == "Email Addresses" and "@" in value:
            local, domain = value.split("@", 1)
            return local[:2] + "***@" + domain
        
        # Default: show first/last 4 chars
        if len(value) > 10:
            return value[:4] + "..." + value[-4:]
        
        return value
