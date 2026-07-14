"""
HTTP Methods Checker Module
Tests for dangerous HTTP methods (TRACE, DELETE, PUT, etc.)
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

METHODS_TO_TEST = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH",
    "OPTIONS", "TRACE", "CONNECT", "TRACK", "DEBUG"
]

DANGEROUS_METHODS = {
    "TRACE": {"risk": "HIGH", "desc": "Enable Cross-Site Tracing (XST) attacks"},
    "TRACK": {"risk": "HIGH", "desc": "Similar to TRACE, leaks headers via requests"},
    "DEBUG": {"risk": "HIGH", "desc": "May expose debug information"},
    "DELETE": {"risk": "MEDIUM", "desc": "Can delete resources if unprotected"},
    "PUT": {"risk": "MEDIUM", "desc": "Can upload/modify resources"},
    "PATCH": {"risk": "LOW", "desc": "Can partially modify resources"},
    "CONNECT": {"risk": "MEDIUM", "desc": "Can establish tunnel connections"},
}

def check_method(url, method, timeout=5):
    try:
        r = requests.request(method, url, timeout=timeout, verify=False, allow_redirects=False)
        return {
            "status": r.status_code,
            "length": len(r.content),
            "headers": dict(r.headers),
            "allowed": r.status_code not in [405, 501]
        }
    except requests.exceptions.RequestException as e:
        return {"status": "ERR", "length": 0, "headers": {}, "allowed": False, "error": str(e)}

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="HTTP Methods Checker")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--methods", nargs="+", help="Specific methods to test")
    parser.add_argument("--timeout", type=float, default=5, help="Request timeout")

    args = parser.parse_args(raw_args)

    url = args.url
    methods = args.methods if args.methods else METHODS_TO_TEST

    console.print(f"[bold cyan]Target:[/bold cyan] {url}")
    console.print(f"[bold cyan]Methods:[/bold cyan] {', '.join(methods)}\n")

    results = []
    for method in methods:
        console.print(f"  [dim]Testing {method}...[/dim]", end="\r")
        result = check_method(url, method, args.timeout)
        results.append({"method": method, **result})

    table = Table(title="HTTP Methods Analysis", border_style="cyan", show_lines=True)
    table.add_column("Method", style="bold")
    table.add_column("Status")
    table.add_column("Allowed", style="bold")
    table.add_column("Size")
    table.add_column("Risk")
    table.add_column("Description")

    issues = []
    for r in results:
        method = r["method"]
        status = str(r["status"])
        allowed = "[green]Yes[/green]" if r["allowed"] else "[red]No[/red]"

        risk_info = DANGEROUS_METHODS.get(method, {})
        risk = risk_info.get("risk", "")
        desc = risk_info.get("desc", "")

        if r["allowed"] and risk in ["HIGH", "MEDIUM"]:
            risk_color = "red" if risk == "HIGH" else "yellow"
            issues.append(f"{method}: {desc}")
            table.add_row(
                method,
                status,
                allowed,
                str(r["length"]),
                f"[{risk_color}]{risk}[/{risk_color}]",
                desc
            )
        else:
            table.add_row(method, status, allowed, str(r["length"]), risk, desc)

    console.print(table)

    # Check for CORS headers
    options_result = check_method(url, "OPTIONS", args.timeout)
    if options_result["allowed"]:
        allow = options_result["headers"].get("Allow", "")
        if allow:
            console.print(f"\n[bold]Allowed Methods (from OPTIONS):[/bold] {allow}")

    # Summary
    enabled_dangerous = [r for r in results if r["allowed"] and r["method"] in DANGEROUS_METHODS]
    if enabled_dangerous:
        console.print(Panel(
            "\n".join(f"  - [red]{m['method']}[/red]: {DANGEROUS_METHODS[m['method']]['desc']}" for m in enabled_dangerous),
            title="[bold red]Dangerous Methods Enabled[/bold red]", border_style="red"
        ))
    else:
        console.print("\n[bold green]No dangerous methods enabled[/bold green]")
