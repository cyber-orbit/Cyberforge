"""
CyberForge URL Analyzer
Provides detailed analysis of URLs including structure, metadata, and risk.
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any


class URLAnalyzer:
    """
    Comprehensive URL analysis tool.
    Breaks down URL components and provides security insights.
    """

    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Perform full structural analysis of a URL.

        Returns dict with all URL components and security flags.
        """
        result = {
            "raw_url": url,
            "scheme": "",
            "domain": "",
            "subdomain": "",
            "tld": "",
            "port": "",
            "path": "",
            "query_params": {},
            "fragment": "",
            "url_length": len(url),
            "is_https": False,
            "is_http": False,
            "has_port": False,
            "has_query": False,
            "has_fragment": False,
            "has_ip": False,
            "has_at_symbol": "@" in url,
            "hyphen_count": 0,
            "subdomain_depth": 0,
            "flags": [],
        }

        try:
            parsed = urlparse(url)

            result["scheme"] = parsed.scheme
            result["is_https"] = parsed.scheme == "https"
            result["is_http"] = parsed.scheme == "http"
            result["path"] = parsed.path
            result["fragment"] = parsed.fragment
            result["has_fragment"] = bool(parsed.fragment)
            result["has_query"] = bool(parsed.query)

            if parsed.query:
                result["query_params"] = parse_qs(parsed.query)

            # Port handling
            if parsed.port:
                result["port"] = str(parsed.port)
                result["has_port"] = True
                if parsed.port not in (80, 443, 8080, 8443):
                    result["flags"].append(f"Non-standard port: {parsed.port}")

            # Domain analysis
            netloc = parsed.netloc
            if ":" in netloc:
                netloc = netloc.split(":")[0]

            result["domain"] = netloc

            # Check if IP address
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc):
                result["has_ip"] = True
                result["flags"].append("IP address used as host")
            else:
                parts = netloc.split(".")
                if len(parts) >= 2:
                    result["tld"] = "." + parts[-1]
                    result["subdomain_depth"] = len(parts) - 2
                    if len(parts) > 2:
                        result["subdomain"] = ".".join(parts[:-2])

            result["hyphen_count"] = netloc.count("-")

            # Security flags
            if result["has_at_symbol"]:
                result["flags"].append("Contains '@' symbol")
            if result["hyphen_count"] > 2:
                result["flags"].append(f"Multiple hyphens: {result['hyphen_count']}")
            if result["url_length"] > 200:
                result["flags"].append(f"Very long URL: {result['url_length']} chars")
            if result["subdomain_depth"] > 2:
                result["flags"].append(f"Deep subdomain: {result['subdomain_depth']} levels")
            if not result["is_https"] and not url.startswith(("file://", "about:")):
                result["flags"].append("No SSL/TLS encryption")
            if url.count("%") > 5:
                result["flags"].append("Heavy URL encoding")

        except Exception as e:
            result["flags"].append(f"Parse error: {str(e)}")

        return result

    def format_report(self, analysis: Dict[str, Any]) -> str:
        """Format analysis dict into a readable text report."""
        lines = [
            "═══ URL Analysis Report ═══",
            f"URL      : {analysis['raw_url'][:80]}{'...' if len(analysis['raw_url']) > 80 else ''}",
            f"Scheme   : {analysis['scheme'].upper() or 'N/A'}",
            f"Domain   : {analysis['domain']}",
        ]
        if analysis['subdomain']:
            lines.append(f"Subdomain: {analysis['subdomain']}")
        if analysis['tld']:
            lines.append(f"TLD      : {analysis['tld']}")
        if analysis['port']:
            lines.append(f"Port     : {analysis['port']}")
        lines.append(f"Path     : {analysis['path'] or '/'}")
        if analysis['has_query']:
            params = list(analysis['query_params'].keys())
            lines.append(f"Params   : {', '.join(params[:5])}")
        lines.append(f"Length   : {analysis['url_length']} chars")
        lines.append(f"HTTPS    : {'✓ Yes' if analysis['is_https'] else '✗ No'}")

        if analysis['flags']:
            lines.append("\n── Security Flags ──")
            for flag in analysis['flags']:
                lines.append(f"  ⚑ {flag}")
        else:
            lines.append("\n✓ No security flags detected")

        return "\n".join(lines)
