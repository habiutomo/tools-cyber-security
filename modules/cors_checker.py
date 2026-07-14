"""
CORS Misconfiguration Checker Module
Checks for Cross-Origin Resource Sharing misconfigurations.
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

def check_cors(url, origin, timeout=5):
    try:
        headers = {
            "Origin": origin,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        }
        r = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        return {
            "status": r.status_code,
            "cors_headers": {
                "Access-Control-Allow-Origin": r.headers.get("Access-Control-Allow-Origin", ""),
                "Access-Control-Allow-Methods": r.headers.get("Access-Control-Allow-Methods", ""),
                "Access-Control-Allow-Headers": r.headers.get("Access-Control-Allow-Headers", ""),
                "Access-Control-Allow-Credentials": r.headers.get("Access-Control-Allow-Credentials", ""),
                "Access-Control-Expose-Headers": r.headers.get("Access-Control-Expose-Headers", ""),
                "Access-Control-Max-Age": r.headers.get("Access-Control-Max-Age", ""),
            },
            "error": None
        }
    except requests.exceptions.RequestException as e:
        return {"status": 0, "cors_headers": {}, "error": str(e)}

def analyze_cors(cors_headers, origin):
    issues = []
    acao = cors_headers.get("Access-Control-Allow-Origin", "")
    acac = cors_headers.get("Access-Control-Allow-Credentials", "")

    if not acao:
        return issues, "NONE"

    if acao == "*":
        if acac.lower() == "true":
            issues.append(("CRITICAL", "Wildcard with credentials",
                          "Allows any origin to make credentialed requests"))
        else:
            issues.append(("MEDIUM", "Wildcard origin",
                          "Allows any origin to read responses"))

    if acao == origin:
        if acac.lower() == "true":
            issues.append(("HIGH", "Reflects origin with credentials",
                          "May allow credential theft from any domain"))

    if acao.startswith("null"):
        issues.append(("HIGH", "Accepts 'null' origin",
                       "Attackers can use sandboxed iframes to send null origin"))

    # Check for trusted subdomains
    if acao != "*" and acao != origin:
        trusted_domain = acao.replace("https://", "").replace("http://", "")
        if not trusted_domain.startswith("."):
            issues.append(("INFO", f"Trusted: {trusted_domain}",
                          "Check if this domain can be compromised"))

    severity = "CRITICAL" if any(i[0] == "CRITICAL" for i in issues) else \
               "HIGH" if any(i[0] == "HIGH" for i in issues) else \
               "MEDIUM" if any(i[0] == "MEDIUM" for i in issues) else "SAFE"

    return issues, severity

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="CORS Misconfiguration Checker")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--origin", default="https://evil.com", help="Origin to test (default: https://evil.com)")
    parser.add_argument("--timeout", type=float, default=5, help="Request timeout")

    args = parser.parse_args(raw_args)

    console.print(f"[bold cyan]Target:[/bold cyan] {args.url}")
    console.print(f"[bold cyan]Origin:[/bold cyan] {args.origin}\n")

    result = check_cors(args.url, args.origin, args.timeout)

    if result["error"]:
        console.print(f"[bold red]Error:[/bold red] {result['error']}")
        sys.exit(1)

    # Display CORS headers
    header_table = Table(title="CORS Headers", border_style="cyan", show_lines=True)
    header_table.add_column("Header", style="bold")
    header_table.add_column("Value", style="green")

    for header, value in result["cors_headers"].items():
        if value:
            header_table.add_row(header, value)

    console.print(header_table)

    # Analyze
    issues, severity = analyze_cors(result["cors_headers"], args.origin)

    if issues:
        issue_table = Table(title="CORS Issues", border_style="red", show_lines=True)
        issue_table.add_column("Severity", style="bold")
        issue_table.add_column("Issue", style="white")
        issue_table.add_column("Description", style="dim")

        for sev, issue, desc in issues:
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}.get(sev, "white")
            issue_table.add_row(f"[{sev_color}]{sev}[/{sev_color}]", issue, desc)

        console.print(issue_table)

    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "SAFE": "green"}.get(severity, "white")
    console.print(f"\n[bold {color}]CORS Security: {severity}[/bold {color}]")
