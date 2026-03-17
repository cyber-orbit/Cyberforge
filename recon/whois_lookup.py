"""
CyberForge WHOIS Lookup
Retrieves domain registration information.
"""

import socket
import re
from typing import Dict


# WHOIS server mapping for common TLDs
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "nl": "whois.domain-registry.nl",
    "ru": "whois.tcinet.ru",
    "cn": "whois.cnnic.cn",
    "jp": "whois.jprs.jp",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "br": "whois.registro.br",
    "in": "whois.registry.in",
    "edu": "whois.educause.edu",
    "gov": "whois.dotgov.gov",
    "mil": "whois.nic.mil",
}

DEFAULT_WHOIS_SERVER = "whois.iana.org"


class WhoisLookup:
    """
    Performs WHOIS queries for domain registration data.
    Uses raw socket connection to WHOIS servers.
    """

    def __init__(self):
        self.timeout = 10

    def lookup(self, domain: str) -> Dict[str, str]:
        """
        Perform WHOIS lookup for a domain.

        Returns dict with WHOIS fields.
        """
        domain = self._clean_domain(domain)
        result = {
            "domain": domain,
            "raw": "",
            "registrar": "",
            "creation_date": "",
            "expiry_date": "",
            "updated_date": "",
            "status": "",
            "name_servers": [],
            "registrant": "",
            "country": "",
            "error": "",
        }

        try:
            # Determine WHOIS server
            tld = domain.split(".")[-1].lower()
            server = WHOIS_SERVERS.get(tld, DEFAULT_WHOIS_SERVER)

            raw = self._raw_whois(domain, server)

            # If IANA refers to another server, follow it
            if "refer:" in raw.lower():
                refer_match = re.search(r"refer:\s*(\S+)", raw, re.IGNORECASE)
                if refer_match:
                    referred_server = refer_match.group(1).strip()
                    if referred_server != server:
                        raw = self._raw_whois(domain, referred_server) or raw

            result["raw"] = raw
            result = self._parse_whois(raw, result)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _clean_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        for prefix in ("https://", "http://", "ftp://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0].split("?")[0]
        # Remove www
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    def _raw_whois(self, domain: str, server: str) -> str:
        """Send WHOIS query via raw TCP socket."""
        try:
            with socket.create_connection((server, 43), timeout=self.timeout) as sock:
                query = f"{domain}\r\n"
                sock.send(query.encode("utf-8"))
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            return response.decode("utf-8", errors="replace")
        except Exception as e:
            return f"[WHOIS connection error: {str(e)}]"

    def _parse_whois(self, raw: str, result: Dict) -> Dict:
        """Parse raw WHOIS response into structured fields."""
        field_map = {
            "registrar": [r"Registrar:\s*(.+)", r"Registrar Name:\s*(.+)"],
            "creation_date": [r"Creation Date:\s*(.+)", r"Created:\s*(.+)", r"Domain Registration Date:\s*(.+)"],
            "expiry_date": [r"Registry Expiry Date:\s*(.+)", r"Expiration Date:\s*(.+)", r"Expires:\s*(.+)"],
            "updated_date": [r"Updated Date:\s*(.+)", r"Last Updated:\s*(.+)"],
            "status": [r"Domain Status:\s*(.+)"],
            "registrant": [r"Registrant Name:\s*(.+)", r"Registrant Organization:\s*(.+)"],
            "country": [r"Registrant Country:\s*(.+)"],
        }

        for field, patterns in field_map.items():
            for pattern in patterns:
                match = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
                if match:
                    result[field] = match.group(1).strip()
                    break

        # Name servers
        ns_matches = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)
        result["name_servers"] = list(set(ns.strip().lower() for ns in ns_matches))[:6]

        return result

    def format_report(self, result: Dict) -> str:
        """Format WHOIS result into readable text."""
        lines = [f"═══ WHOIS: {result['domain']} ═══", ""]

        if result.get("error"):
            lines.append(f"⚠ Error: {result['error']}")
            return "\n".join(lines)

        fields = [
            ("Registrar", result.get("registrar")),
            ("Registrant", result.get("registrant")),
            ("Country", result.get("country")),
            ("Created", result.get("creation_date")),
            ("Expires", result.get("expiry_date")),
            ("Updated", result.get("updated_date")),
            ("Status", result.get("status")),
        ]

        for label, value in fields:
            if value:
                lines.append(f"{label:12}: {value[:60]}")

        if result.get("name_servers"):
            lines.append(f"{'Name Servers':12}:")
            for ns in result["name_servers"]:
                lines.append(f"              {ns}")

        if not any(v for _, v in fields):
            lines.append("No structured data found. See raw output.")
            if result.get("raw"):
                lines.append("\n── Raw Output (first 500 chars) ──")
                lines.append(result["raw"][:500])

        return "\n".join(lines)
