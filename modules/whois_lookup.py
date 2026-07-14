"""
WHOIS Lookup Module
Queries WHOIS information for a domain or IP address.
"""

import argparse
import sys
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def run(raw_args=None):
    if not HAS_WHOIS:
        console.print("[bold red]Error:[/bold red] python-whois not installed. Run: pip install python-whois")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="WHOIS Lookup")
    parser.add_argument("-t", "--target", required=True, help="Domain or IP address")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args(raw_args)

    console.print(f"[bold cyan]WHOIS Lookup for:[/bold cyan] {args.target}\n")

    try:
        w = whois.whois(args.target)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

    fields = {
        "Domain Name": w.domain_name,
        "Registrar": w.registrar,
        "Creation Date": w.creation_date,
        "Expiration Date": w.expiration_date,
        "Updated Date": w.updated_date,
        "Name Servers": w.name_servers,
        "Status": w.status,
        "Registrant Name": getattr(w, "org", None) or getattr(w, "name", None),
        "Registrant Country": w.country,
        "Registrant State": w.state,
        "Registrant City": w.city,
        "Registrant Email": w.emails,
        "DNSSEC": w.dnssec,
    }

    table = Table(title=f"WHOIS: {args.target}", border_style="green", show_lines=True)
    table.add_column("Field", style="bold cyan", min_width=20)
    table.add_column("Value", style="white")

    output_lines = []
    for key, value in fields.items():
        if value is not None:
            if isinstance(value, list):
                value = "\n".join(str(v) for v in value)
            table.add_row(key, str(value))
            output_lines.append(f"{key}: {value}")

    console.print(table)

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"WHOIS Information for {args.target}\n")
            f.write("=" * 50 + "\n\n")
            for line in output_lines:
                f.write(f"{line}\n\n")
        console.print(f"[dim]Results saved to {args.output}[/dim]")
