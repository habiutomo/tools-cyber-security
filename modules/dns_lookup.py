"""
DNS Lookup Module
Queries various DNS record types for a domain.
"""

import argparse
import sys
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA", "PTR", "SOA"]

def query_dns(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        records = []
        for rdata in answers:
            records.append(str(rdata))
        return records
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoNameservers:
        return []
    except Exception as e:
        return [f"Error: {e}"]

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="DNS Lookup")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-t", "--type", nargs="+", default=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
                        help="Record types to query (default: A AAAA MX NS TXT CNAME SOA)")
    parser.add_argument("--all", action="store_true", help="Query all record types")

    args = parser.parse_args(raw_args)

    record_types = RECORD_TYPES if args.all else [r.upper() for r in args.type]

    console.print(f"[bold cyan]DNS Lookup for:[/bold cyan] {args.domain}\n")

    for rtype in record_types:
        records = query_dns(args.domain, rtype)
        if records:
            table = Table(border_style="cyan", title=f"{rtype} Records", title_style="bold")
            table.add_column("Record", style="green")
            for rec in records:
                table.add_row(rec)
            console.print(table)
            console.print()
        else:
            console.print(f"  [dim]{rtype}: No records found[/dim]")

    # Additional info
    console.print(Panel(
        f"[bold cyan]Domain:[/bold cyan] {args.domain}\n"
        f"[bold cyan]Queried Types:[/bold cyan] {', '.join(record_types)}",
        title="Summary", border_style="yellow"
    ))
