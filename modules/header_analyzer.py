"""
HTTP Header Analyzer Module
Analyzes HTTP response headers for security misconfigurations.
"""

import argparse
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "severity": "HIGH",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS, clickjacking, code injection",
        "severity": "HIGH",
        "recommendation": "Configure a strict CSP policy"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
        "recommendation": "Set to 'DENY' or 'SAMEORIGIN'"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing",
        "severity": "MEDIUM",
        "recommendation": "Set to 'nosniff'"
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filter",
        "severity": "LOW",
        "recommendation": "Set to '1; mode=block'"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "MEDIUM",
        "recommendation": "Set to 'strict-origin-when-cross-origin' or 'no-referrer'"
    },
    "Permissions-Policy": {
        "description": "Controls browser features access",
        "severity": "LOW",
        "recommendation": "Restrict unnecessary browser features"
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context",
        "severity": "LOW",
        "recommendation": "Set to 'same-origin'"
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents cross-origin reads",
        "severity": "LOW",
        "recommendation": "Set to 'same-origin'"
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Enables cross-origin isolation",
        "severity": "LOW",
        "recommendation": "Set to 'require-corp'"
    },
}

INSECURE_HEADERS = {
    "Server": "Reveals server software",
    "X-Powered-By": "Reveals technology stack",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-AspNetMvc-Version": "Reveals MVC version",
}

def analyze_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        return response
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="HTTP Header Analyzer")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--all-headers", action="store_true", help="Show all response headers")

    args = parser.parse_args(raw_args)

    response = analyze_url(args.url)
    headers = dict(response.headers)

    console.print(f"[bold cyan]URL:[/bold cyan] {response.url}")
    console.print(f"[bold cyan]Status:[/bold cyan] {response.status_code}")
    console.print(f"[bold cyan]Server:[/bold cyan] {headers.get('Server', 'N/A')}\n")

    # Missing security headers
    missing = []
    present = []
    for header, info in SECURITY_HEADERS.items():
        if header.lower() in [h.lower() for h in headers]:
            value = next(v for k, v in headers.items() if k.lower() == header.lower())
            present.append((header, value, info))
        else:
            missing.append((header, info))

    if present:
        table = Table(title="Present Security Headers", border_style="green", show_lines=True)
        table.add_column("Header", style="bold cyan")
        table.add_column("Value", style="green", max_width=60)
        table.add_column("Description", style="dim")
        for header, value, info in present:
            table.add_row(header, value[:80], info["description"])
        console.print(table)
        console.print()

    if missing:
        table = Table(title="Missing Security Headers", border_style="red", show_lines=True)
        table.add_column("Header", style="bold red")
        table.add_column("Severity", style="yellow")
        table.add_column("Recommendation", style="dim")
        for header, info in missing:
            table.add_row(header, info["severity"], info["recommendation"])
        console.print(table)
        console.print()

    # Information disclosure
    disclosed = []
    for header, desc in INSECURE_HEADERS.items():
        if header.lower() in [h.lower() for h in headers]:
            value = next(v for k, v in headers.items() if k.lower() == header.lower())
            disclosed.append((header, value, desc))

    if disclosed:
        table = Table(title="Information Disclosure", border_style="yellow", show_lines=True)
        table.add_column("Header", style="bold yellow")
        table.add_column("Value", style="yellow")
        table.add_column("Risk", style="red")
        for header, value, desc in disclosed:
            table.add_row(header, value, desc)
        console.print(table)
        console.print()

    # All headers if requested
    if args.all_headers:
        table = Table(title="All Response Headers", border_style="dim", show_lines=True)
        table.add_column("Header", style="bold")
        table.add_column("Value", max_width=80)
        for k, v in headers.items():
            table.add_row(k, v)
        console.print(table)

    # Score
    total = len(SECURITY_HEADERS)
    found = len(present)
    score = int((found / total) * 100)
    color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    console.print(f"\n[bold {color}]Security Header Score: {score}%[/bold {color}] ({found}/{total})")
