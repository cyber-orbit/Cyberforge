"""
CyberForge Subdomain Lookup
Discovers subdomains via DNS brute-force with a wordlist.
"""

import socket
import concurrent.futures
from typing import List, Dict, Callable, Optional

# Common subdomains to check
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "mx1", "mx2", "blog", "dev", "staging", "api", "admin",
    "vpn", "ssh", "sftp", "server", "portal", "test", "m", "mobile", "cdn",
    "static", "assets", "images", "img", "media", "download", "downloads",
    "docs", "help", "support", "status", "git", "gitlab", "jira", "wiki",
    "backup", "old", "new", "beta", "alpha", "demo", "app", "apps",
    "dashboard", "cpanel", "whm", "webdisk", "autodiscover", "remote",
    "shop", "store", "pay", "payment", "secure", "ssl", "intranet",
    "db", "database", "sql", "mysql", "phpmyadmin", "ftp2", "monitor",
    "email", "webservice", "ws", "news", "forum", "community", "chat",
    "irc", "conference", "meet", "video", "audio", "stream",
]


class SubdomainLookup:
    """
    Subdomain enumeration via DNS resolution.
    Uses concurrent threading for speed.
    """

    def __init__(self):
        self.timeout = 3
        self.max_workers = 30

    def scan(self, domain: str,
             progress_callback: Optional[Callable] = None,
             wordlist: Optional[List[str]] = None) -> Dict:
        """
        Scan for subdomains of a given domain.

        Args:
            domain: Target domain (e.g., example.com)
            progress_callback: Optional fn(current, total) for progress updates
            wordlist: Custom subdomain wordlist; defaults to COMMON_SUBDOMAINS

        Returns:
            Dict with found subdomains and metadata
        """
        domain = self._clean_domain(domain)
        wordlist = wordlist or COMMON_SUBDOMAINS

        results = {
            "domain": domain,
            "found": [],
            "total_checked": len(wordlist),
            "error": "",
        }

        found = []
        total = len(wordlist)

        def check_subdomain(sub: str) -> Optional[Dict]:
            fqdn = f"{sub}.{domain}"
            try:
                ips = socket.getaddrinfo(fqdn, None, timeout=self.timeout)
                ip_list = list(set(info[4][0] for info in ips))
                return {"subdomain": fqdn, "ips": ip_list}
            except (socket.gaierror, OSError):
                return None

        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in wordlist}

            for future in concurrent.futures.as_completed(future_to_sub):
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
                result = future.result()
                if result:
                    found.append(result)

        # Sort by subdomain name
        results["found"] = sorted(found, key=lambda x: x["subdomain"])
        return results

    def _clean_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    def format_report(self, results: Dict) -> str:
        """Format subdomain scan results."""
        lines = [f"═══ Subdomain Scan: {results['domain']} ═══", ""]
        lines.append(f"Checked : {results['total_checked']} subdomains")
        lines.append(f"Found   : {len(results['found'])} active subdomain(s)")
        lines.append("")

        if results.get("error"):
            lines.append(f"⚠ Error: {results['error']}")

        if results["found"]:
            lines.append("── Active Subdomains ──")
            for item in results["found"]:
                ips = ", ".join(item["ips"])
                lines.append(f"  ✓ {item['subdomain']}")
                lines.append(f"      IP(s): {ips}")
        else:
            lines.append("No active subdomains found from wordlist.")

        return "\n".join(lines)
