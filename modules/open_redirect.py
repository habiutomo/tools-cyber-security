"""
Open Redirect Checker Module
Detects open redirect vulnerabilities in web applications.
"""

import argparse
import sys
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table

console = Console()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return_url",
    "return_to", "next", "continue", "dest", "destination", "redir",
    "redirect_to", "login_url", "return_url", "rurl", "link",
    "go", "goto", "out", "view", "to", "path", "ref", "referer",
    "site", "page", "target", "forward", "forward_url", "location"
]

PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "https://evil.com%23.target.com",
    "https://evil.com?.target.com",
    "//evil.com%0d%0aLocation:%20https://evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

def test_redirect(base_url, param, payload, timeout=5):
    try:
        parsed = urlparse(base_url)
        original_params = parse_qs(parsed.query)

        test_params = dict(original_params)
        test_params[param] = payload

        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if test_params:
            test_url += "?" + urlencode(test_params, doseq=True)

        r = requests.get(base_url, params={param: payload},
                        timeout=timeout, verify=False, allow_redirects=False)

        location = r.headers.get("Location", "")
        is_redirect = r.status_code in [301, 302, 303, 307, 308]

        vulnerable = False
        if is_redirect and location:
            if payload in location or "evil.com" in location:
                vulnerable = True
            elif not location.startswith("/") and "evil.com" in location:
                vulnerable = True

        return {
            "param": param,
            "payload": payload,
            "status": r.status_code,
            "redirect": is_redirect,
            "location": location,
            "vulnerable": vulnerable
        }
    except requests.exceptions.RequestException:
        return None

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Open Redirect Checker")
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameters")
    parser.add_argument("-p", "--params", nargs="+", help="Specific params to test")
    parser.add_argument("--timeout", type=float, default=5, help="Request timeout")

    args = parser.parse_args(raw_args)

    parsed = urlparse(args.url)
    existing_params = list(parse_qs(parsed.query).keys())
    params_to_test = args.params if args.params else (existing_params if existing_params else REDIRECT_PARAMS[:10])

    console.print(f"[bold cyan]Target:[/bold cyan] {args.url}")
    console.print(f"[bold cyan]Params to test:[/bold cyan] {', '.join(params_to_test)}")
    console.print(f"[bold cyan]Payloads:[/bold cyan] {len(PAYLOADS)}\n")

    results = []
    total = len(params_to_test) * len(PAYLOADS)

    for param in params_to_test:
        for payload in PAYLOADS:
            console.print(f"  [dim]Testing {param}={payload[:30]}...[/dim]", end="\r")
            result = test_redirect(args.url, param, payload, args.timeout)
            if result and result["vulnerable"]:
                results.append(result)

    if results:
        table = Table(title="Open Redirect Vulnerabilities Found", border_style="red", show_lines=True)
        table.add_column("Parameter", style="bold cyan")
        table.add_column("Payload", style="yellow")
        table.add_column("Status")
        table.add_column("Redirect To", style="red")

        for r in results:
            table.add_row(r["param"], r["payload"][:40], str(r["status"]), r["location"][:60])

        console.print(table)
        console.print(f"\n[bold red]{len(results)} open redirect vulnerability(ies) found![/bold red]")
    else:
        console.print("[bold green]No open redirect vulnerabilities found[/bold green]")
