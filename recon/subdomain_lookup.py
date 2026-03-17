"""
CyberForge Subdomain Lookup
Discovers subdomains via DNS brute-force with a wordlist.
"""

import socket
import concurrent.futures
from typing import List, Dict, Callable, Optional
import time

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
                # Set socket timeout globally for this thread
                original_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(self.timeout)
                
                try:
                    ips = socket.getaddrinfo(fqdn, None)
                    ip_list = list(set(info[4][0] for info in ips))
                    return {"subdomain": fqdn, "ips": ip_list}
                finally:
                    # Restore original timeout
                    socket.setdefaulttimeout(original_timeout)
                    
            except (socket.gaierror, OSError, socket.timeout):
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
        for prefix in ("https://", "http://", "ftp://", "ftps://"):
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


# Alternative version using socket.create_connection for better timeout control
class SubdomainLookupAlt:
    """
    Alternative implementation using socket.create_connection
    for more reliable timeout handling.
    """

    def __init__(self):
        self.timeout = 3
        self.max_workers = 30

    def scan(self, domain: str,
             progress_callback: Optional[Callable] = None,
             wordlist: Optional[List[str]] = None) -> Dict:
        
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
                # Try to resolve using gethostbyname_ex with timeout via threading
                ip_list = []
                
                # Method 1: Try standard resolution
                try:
                    _, _, ips = socket.gethostbyname_ex(fqdn)
                    ip_list = ips
                except (socket.gaierror, OSError):
                    # Method 2: Try getaddrinfo
                    try:
                        addr_info = socket.getaddrinfo(fqdn, None)
                        ip_list = list(set(info[4][0] for info in addr_info))
                    except (socket.gaierror, OSError):
                        return None
                
                if ip_list:
                    return {"subdomain": fqdn, "ips": ip_list}
                return None
                
            except Exception:
                return None

        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_sub = {
                executor.submit(check_subdomain, sub): sub 
                for sub in wordlist
            }

            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_sub, timeout=self.timeout * 2):
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
                
                try:
                    result = future.result(timeout=self.timeout)
                    if result:
                        found.append(result)
                except (concurrent.futures.TimeoutError, Exception):
                    continue

        # Sort by subdomain name
        results["found"] = sorted(found, key=lambda x: x["subdomain"])
        return results

    def _clean_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        for prefix in ("https://", "http://", "ftp://", "ftps://"):
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


# Test function
if __name__ == "__main__":
    # Test the subdomain scanner
    scanner = SubdomainLookup()
    
    def progress(current, total):
        print(f"Progress: {current}/{total} ({current/total*100:.1f}%)")
    
    # Test with a real domain
    print("Scanning example.com...")
    results = scanner.scan("example.com", progress_callback=progress)
    print(scanner.format_report(results))
    
    # Test with custom wordlist
    print("\n" + "="*50)
    print("Testing with custom wordlist...")
    custom_wordlist = ["www", "mail", "test", "dev", "api"]
    results = scanner.scan("google.com", wordlist=custom_wordlist)
    print(scanner.format_report(results))
