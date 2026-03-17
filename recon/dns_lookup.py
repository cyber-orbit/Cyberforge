"""
CyberForge DNS Lookup
Performs DNS queries for reconnaissance.
"""

import socket
from typing import Dict, List

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSLookup:
    """
    DNS reconnaissance tool.
    Queries A, MX, NS, TXT, AAAA records for a domain.
    """

    def __init__(self):
        self.available = DNS_AVAILABLE

    def lookup(self, domain: str) -> Dict[str, List[str]]:
        """
        Perform comprehensive DNS lookup for a domain.
        Falls back to socket if dnspython is unavailable.
        """
        domain = self._clean_domain(domain)
        results = {
            "domain": domain,
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": [],
            "errors": [],
        }

        if self.available:
            results = self._dns_lookup(domain, results)
        else:
            results = self._socket_lookup(domain, results)

        return results

    def _clean_domain(self, domain: str) -> str:
        """Strip protocol and path from domain input."""
        domain = domain.strip().lower()
        for prefix in ("https://", "http://", "ftp://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0].split("?")[0]
        return domain

    def _dns_lookup(self, domain: str, results: Dict) -> Dict:
        """Use dnspython for full DNS resolution."""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                for rdata in answers:
                    if rtype == "MX":
                        results[rtype].append(f"{rdata.exchange} (priority: {rdata.preference})")
                    elif rtype == "TXT":
                        results[rtype].append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
                    else:
                        results[rtype].append(str(rdata))
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                results["errors"].append(f"Domain '{domain}' does not exist (NXDOMAIN)")
                break
            except dns.resolver.Timeout:
                results["errors"].append(f"Timeout resolving {rtype} for {domain}")
            except Exception as e:
                results["errors"].append(f"{rtype} error: {str(e)}")

        return results

    def _socket_lookup(self, domain: str, results: Dict) -> Dict:
        """Fallback: basic A record lookup via socket."""
        try:
            infos = socket.getaddrinfo(domain, None)
            for info in infos:
                ip = info[4][0]
                if ":" in ip and ip not in results["AAAA"]:
                    results["AAAA"].append(ip)
                elif ip not in results["A"]:
                    results["A"].append(ip)
        except socket.gaierror as e:
            results["errors"].append(f"DNS resolution failed: {str(e)}")
        results["errors"].append("Note: dnspython not installed — limited to A/AAAA records")
        return results

    def format_report(self, results: Dict) -> str:
        """Format DNS results into a readable report."""
        lines = [f"═══ DNS Lookup: {results['domain']} ═══", ""]

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        for rtype in record_types:
            if results.get(rtype):
                lines.append(f"── {rtype} Records ──")
                for record in results[rtype]:
                    lines.append(f"  {record}")
                lines.append("")

        if results.get("errors"):
            lines.append("── Errors / Notes ──")
            for err in results["errors"]:
                lines.append(f"  ⚠ {err}")

        if not any(results.get(rt) for rt in record_types):
            lines.append("No DNS records found.")

        return "\n".join(lines)

    def reverse_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup on an IP address."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return f"{ip} → {hostname}"
        except socket.herror:
            return f"{ip} → No reverse DNS entry"
        except Exception as e:
            return f"Reverse lookup error: {str(e)}"
