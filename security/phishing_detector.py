"""
CyberForge Phishing Detector
Analyzes URLs for phishing indicators using heuristics and pattern matching.
"""

import re
from urllib.parse import urlparse
from typing import Tuple, List


# Known safe domains (whitelist)
SAFE_DOMAINS = {
    "google.com", "www.google.com",
    "github.com", "www.github.com",
    "wikipedia.org", "www.wikipedia.org",
    "stackoverflow.com", "www.stackoverflow.com",
    "mozilla.org", "www.mozilla.org",
    "python.org", "www.python.org",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com",
    "youtube.com", "www.youtube.com",
    "twitter.com", "www.twitter.com",
    "facebook.com", "www.facebook.com",
    "linkedin.com", "www.linkedin.com",
    "reddit.com", "www.reddit.com",
    "cloudflare.com", "www.cloudflare.com",
}

# Suspicious keywords often found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "secure", "update", "confirm", "banking",
    "paypal", "ebay", "amazon", "apple", "microsoft",
    "netflix", "password", "credential", "wallet",
    "authenticate", "suspend", "locked", "billing",
    "urgent", "alert", "validate", "click", "free",
]

# Known phishing TLDs (high-risk)
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".download",
    ".loan", ".work", ".date", ".faith",
    ".bid", ".win", ".review", ".trade",
}

# Legitimate brands often spoofed
SPOOFED_BRANDS = [
    "paypal", "apple", "amazon", "microsoft", "google",
    "netflix", "facebook", "instagram", "twitter", "bank",
    "ebay", "chase", "wellsfargo", "citibank", "hsbc",
]


class PhishingDetector:
    """
    Analyzes URLs for phishing risk using multiple heuristics.
    Returns a risk score and list of reasons.
    """

    def __init__(self):
        self.phishing_keywords = PHISHING_KEYWORDS
        self.suspicious_tlds = SUSPICIOUS_TLDS
        self.spoofed_brands = SPOOFED_BRANDS
        self.safe_domains = SAFE_DOMAINS

    def analyze(self, url: str) -> Tuple[str, int, List[str]]:
        """
        Analyze a URL for phishing risk.

        Returns:
            Tuple of (risk_level, score, reasons)
            risk_level: "safe", "unknown", "suspicious"
            score: 0-100 risk score
            reasons: list of detected issues
        """
        if not url or url.startswith("about:") or url.startswith("file://"):
            return "safe", 0, []

        reasons = []
        score = 0

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()

            # Strip www for comparison
            clean_domain = domain.replace("www.", "")

            # Check whitelist
            if domain in self.safe_domains or clean_domain in self.safe_domains:
                return "safe", 5, ["Trusted domain"]

            # 1. Check for IP address instead of domain
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain):
                reasons.append("⚠ IP address used instead of domain name")
                score += 30

            # 2. Check for suspicious TLD
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    reasons.append(f"⚠ High-risk TLD detected: {tld}")
                    score += 25
                    break

            # 3. Check URL length (very long URLs are suspicious)
            if len(url) > 100:
                reasons.append(f"⚠ Unusually long URL ({len(url)} chars)")
                score += 10
            if len(url) > 200:
                score += 15

            # 4. Check for excessive subdomains
            subdomain_count = domain.count(".")
            if subdomain_count > 3:
                reasons.append(f"⚠ Excessive subdomains ({subdomain_count} dots)")
                score += 20

            # 5. Check for phishing keywords in URL
            found_keywords = []
            for keyword in self.phishing_keywords:
                if keyword in full_url:
                    found_keywords.append(keyword)
            if found_keywords:
                reasons.append(f"⚠ Suspicious keywords: {', '.join(found_keywords[:3])}")
                score += min(len(found_keywords) * 8, 30)

            # 6. Check for brand spoofing (brand in subdomain/path but not main domain)
            for brand in self.spoofed_brands:
                if brand in domain and clean_domain != f"{brand}.com":
                    # E.g. paypal-secure.com or secure-paypal.tk
                    reasons.append(f"⚠ Possible brand spoofing: '{brand}' in domain")
                    score += 35
                    break

            # 7. Check for @-symbol in URL (tricks browsers)
            if "@" in url:
                reasons.append("⚠ '@' symbol in URL (credential theft trick)")
                score += 40

            # 8. Check for double slash in path
            if "//" in path:
                reasons.append("⚠ Double slash in URL path (redirection trick)")
                score += 15

            # 9. Check for hex encoding in URL
            if "%" in url and url.count("%") > 5:
                reasons.append("⚠ Heavy URL encoding (obfuscation attempt)")
                score += 20

            # 10. HTTP (not HTTPS)
            if parsed.scheme == "http":
                reasons.append("⚠ Unencrypted HTTP connection (no SSL)")
                score += 15

            # 11. Hyphens in domain (common phishing trick)
            if domain.count("-") > 2:
                reasons.append(f"⚠ Multiple hyphens in domain ({domain.count('-')} found)")
                score += 10

            # 12. Numeric domain
            if re.search(r"\d{5,}", domain):
                reasons.append("⚠ Suspicious numeric sequence in domain")
                score += 15

        except Exception as e:
            reasons.append(f"⚠ URL parse error: {str(e)}")
            score += 10

        # Determine risk level
        score = min(score, 100)
        if score >= 50:
            risk_level = "suspicious"
        elif score >= 20:
            risk_level = "unknown"
        else:
            risk_level = "safe"
            if not reasons:
                reasons = ["No obvious phishing indicators found"]

        return risk_level, score, reasons

    def is_safe(self, url: str) -> bool:
        risk, score, _ = self.analyze(url)
        return risk == "safe"

    def get_color(self, risk_level: str) -> str:
        """Return color hex for risk level."""
        colors = {
            "safe": "#00ff88",
            "unknown": "#ffcc00",
            "suspicious": "#ff4444",
        }
        return colors.get(risk_level, "#ffcc00")
