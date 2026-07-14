"""
URL Checker Module
Checks URLs for phishing indicators and security issues.
"""

import argparse
import re
import sys
from urllib.parse import urlparse, parse_qs
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".work", ".buzz", ".icu", ".cam", ".rest", ".sbs", ".cfd"
]

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "suspend", "restrict", "urgent", "alert",
    "signin", "authenticate", "credential", "paypal", "apple",
    "microsoft", "google", "amazon", "netflix", "facebook"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"
]

def analyze_url(url):
    results = {
        "url": url,
        "issues": [],
        "score": 100,
        "checks": {}
    }

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path
    query = parsed.query

    # Check HTTPS
    if parsed.scheme != "https":
        results["issues"].append(("HIGH", "Not using HTTPS", "Site does not use encrypted connection"))
        results["score"] -= 20
    results["checks"]["https"] = parsed.scheme == "https"

    # Check IP address instead of domain
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(hostname):
        results["issues"].append(("HIGH", "Uses IP address instead of domain", "Phishing sites often use IPs"))
        results["score"] -= 15
    results["checks"]["uses_ip"] = bool(ip_pattern.match(hostname))

    # Check suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            results["issues"].append(("MEDIUM", f"Suspicious TLD ({tld})", "Commonly used by phishing sites"))
            results["score"] -= 10
            break
    results["checks"]["suspicious_tld"] = any(hostname.endswith(t) for t in SUSPICIOUS_TLDS)

    # Check URL shorteners
    for shortener in SHORTENERS:
        if hostname == shortener or hostname.endswith("." + shortener):
            results["issues"].append(("MEDIUM", "URL shortener detected", "Shorteners can hide malicious URLs"))
            results["score"] -= 10
            break
    results["checks"]["shortened"] = any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS)

    # Check phishing keywords in URL
    full_url = url.lower()
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    if found_keywords:
        results["issues"].append(("MEDIUM", f"Phishing keywords: {', '.join(found_keywords[:5])}",
                                   "These words are commonly used in phishing URLs"))
        results["score"] -= 5 * min(len(found_keywords), 3)
    results["checks"]["phishing_keywords"] = found_keywords

    # Check for excessive subdomains
    parts = hostname.split(".")
    if len(parts) > 3:
        results["issues"].append(("MEDIUM", "Excessive subdomains", "May be masking the real domain"))
        results["score"] -= 10
    results["checks"]["subdomain_depth"] = len(parts)

    # Check for @ in URL (credential phishing)
    if "@" in url.split("//")[-1]:
        results["issues"].append(("HIGH", "Contains @ character", "Common technique to disguise URLs"))
        results["score"] -= 25
    results["checks"]["has_at_sign"] = "@" in url.split("//")[-1]

    # Check for double slashes in path (redirect trick)
    if "//" in path:
        results["issues"].append(("MEDIUM", "Double slash in path", "May indicate redirect trick"))
        results["score"] -= 10

    # Check for very long URL
    if len(url) > 200:
        results["issues"].append(("LOW", "Very long URL", "Phishing URLs are often unusually long"))
        results["score"] -= 5

    # Check port usage
    if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
        results["issues"].append(("LOW", f"Unusual port ({parsed.port})", "Phishing sites may use non-standard ports"))
        results["score"] -= 5

    # Check query parameters for data exfiltration indicators
    if query:
        params = parse_qs(query)
        suspicious_params = [p for p in params if any(kw in p.lower() for kw in ["redirect", "url", "return", "next", "continue"])]
        if suspicious_params:
            results["issues"].append(("MEDIUM", f"Suspicious redirect params: {suspicious_params}",
                                       "May be used for redirect attacks"))
            results["score"] -= 10

    results["score"] = max(0, results["score"])
    return results

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="URL/Phishing Checker")
    parser.add_argument("urls", nargs="+", help="URL(s) to check")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed analysis")

    args = parser.parse_args(raw_args)

    for url in args.urls:
        results = analyze_url(url)

        if results["score"] >= 80:
            color = "green"
            verdict = "LIKELY SAFE"
        elif results["score"] >= 60:
            color = "yellow"
            verdict = "SUSPICIOUS"
        elif results["score"] >= 40:
            color = "yellow"
            verdict = "RISKY"
        else:
            color = "red"
            verdict = "LIKELY MALICIOUS"

        console.print(Panel(
            f"[bold {color}]Verdict: {verdict}[/bold {color}]\n"
            f"[bold cyan]Score:[/bold cyan] {results['score']}/100\n"
            f"[bold cyan]URL:[/bold cyan] {results['url']}\n"
            f"[bold cyan]Issues:[/bold cyan] {len(results['issues'])}",
            title="[bold]URL Safety Analysis[/bold]", border_style=color
        ))

        if results["issues"]:
            table = Table(show_lines=True, border_style=color)
            table.add_column("Severity", style="bold")
            table.add_column("Issue", style="white")
            table.add_column("Description", style="dim")

            for severity, issue, desc in results["issues"]:
                sev_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(severity, "white")
                table.add_row(f"[{sev_color}]{severity}[/{sev_color}]", issue, desc)

            console.print(table)

        if args.verbose:
            console.print("\n[bold]Detailed Checks:[/bold]")
            for check, result in results["checks"].items():
                status = "PASS" if not result else ("WARN" if isinstance(result, (list, bool)) else "INFO")
                console.print(f"  {check}: {result}")

        console.print()
