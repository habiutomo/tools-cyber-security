"""
Reverse IP Lookup Module
Finds all domains hosted on an IP address.
"""

import argparse
import socket
import sys
import requests
from rich.console import Console
from rich.table import Table

console = Console()

def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def reverse_ip_hackertarget(ip):
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
        if r.status_code == 200 and "error" not in r.text.lower():
            return [line.strip() for line in r.text.strip().split("\n") if line.strip()]
    except:
        pass
    return []

def get_shodan_data(ip):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Reverse IP Lookup")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("--shodan", action="store_true", help="Include Shodan port/vuln data")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args(raw_args)

    ip = resolve_ip(args.target)
    if not ip:
        console.print(f"[bold red]Error:[/bold red] Cannot resolve '{args.target}'")
        sys.exit(1)

    console.print(f"[bold cyan]Target:[/bold cyan] {args.target} ({ip})\n")

    all_domains = set()

    console.print("[dim]Querying HackerTarget API...[/dim]")
    ht_domains = reverse_ip_hackertarget(ip)
    all_domains.update(ht_domains)

    if all_domains:
        domains = sorted(all_domains)
        table = Table(title=f"Domains on {ip} ({len(domains)} found)", border_style="green")
        table.add_column("#", style="dim")
        table.add_column("Domain", style="cyan")

        for i, d in enumerate(domains, 1):
            table.add_row(str(i), d)

        console.print(table)

        if args.output:
            with open(args.output, "w") as f:
                for d in domains:
                    f.write(f"{d}\n")
            console.print(f"[dim]Results saved to {args.output}[/dim]")
    else:
        console.print("[yellow]No domains found via reverse IP lookup[/yellow]")

    # Shodan data
    if args.shodan:
        console.print(f"\n[bold cyan]Querying Shodan for {ip}...[/bold cyan]")
        data = get_shodan_data(ip)
        if data:
            shodan_table = Table(title="Shodan Intelligence", border_style="yellow", show_lines=True)
            shodan_table.add_column("Field", style="bold")
            shodan_table.add_column("Value")

            shodan_table.add_row("Hostnames", ", ".join(data.get("hostnames", [])))
            shodan_table.add_row("Ports", ", ".join(str(p) for p in data.get("ports", [])))
            shodan_table.add_row("CPES", ", ".join(data.get("cpes", [])))
            shodan_table.add_row("OS", str(data.get("os", "N/A")))

            vulns = data.get("vulns", [])
            if vulns:
                shodan_table.add_row("Vulnerabilities", "\n".join(vulns))
            else:
                shodan_table.add_row("Vulnerabilities", "None found")

            tags = data.get("tags", [])
            if tags:
                shodan_table.add_row("Tags", ", ".join(tags))

            console.print(shodan_table)
        else:
            console.print("[dim]Shodan data unavailable[/dim]")
