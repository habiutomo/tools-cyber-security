"""
Subdomain Enumeration Module
Enumerates subdomains using DNS brute-force and wordlists.
"""

import socket
import argparse
import threading
import sys
import os
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()
results = []
lock = threading.Lock()

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "webmail",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "admin", "administrator", "webmaster", "hostmaster", "postmaster",
    "dev", "development", "staging", "test", "testing", "sandbox", "demo",
    "api", "api2", "rest", "graphql", "ws", "socket",
    "app", "mobile", "m", "wap",
    "blog", "forum", "community", "support", "help", "docs", "wiki",
    "portal", "intranet", "extranet", "vpn", "remote", "gateway",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "git", "gitlab", "github", "svn", "ci", "jenkins", "travis",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "backup", "bak", "old", "archive", "downloads",
    "shop", "store", "cart", "pay", "payment", "billing",
    "crm", "erp", "hr", "jira", "confluence", "slack",
    "mx", "mx1", "mx2", "mail1", "mail2", "email",
    "cpanel", "whm", "plesk", "webmin",
    "autodiscover", "autoconfig", "owa", "exchange", "lync", "sip",
    "proxy", "load", "balancer", "haproxy", "nginx", "apache",
    "status", "monitor", "grafana", "kibana", "prometheus",
    "i", "intranet", "my", "portal", "secure", "login", "auth",
    "sso", "id", "accounts", "oauth",
    "search", "solr", "elastic", "elasticsearch",
    "log", "logs", "syslog", "sentry",
    "ntp", "ldap", "kerberos", "ad", "dc",
    "edge", "internal", "private", "secure", "s"
]

def check_subdomain(domain, subdomain):
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        with lock:
            results.append({"subdomain": fqdn, "ip": ip})
        return True
    except socket.gaierror:
        return False

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Subdomain Enumeration")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file (one word per line)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args(raw_args)

    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            console.print(f"[bold red]Error:[/bold red] Wordlist not found: {args.wordlist}")
            sys.exit(1)
        with open(args.wordlist, "r") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    else:
        wordlist = DEFAULT_WORDLIST

    console.print(f"[bold cyan]Domain:[/bold cyan] {args.domain}")
    console.print(f"[bold cyan]Wordlist:[/bold cyan] {len(wordlist)} words")
    console.print(f"[bold cyan]Threads:[/bold cyan] {args.threads}\n")

    global results
    results = []

    with Progress(BarColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Enumerating subdomains...", total=len(wordlist))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(check_subdomain, args.domain, word): word
                for word in wordlist
            }
            for future in as_completed(futures):
                future.result()
                progress.advance(task)

    if results:
        results.sort(key=lambda x: x["subdomain"])

        table = Table(title=f"Subdomains for {args.domain}", border_style="green")
        table.add_column("#", style="dim")
        table.add_column("Subdomain", style="bold cyan")
        table.add_column("IP Address", style="yellow")

        for i, r in enumerate(results, 1):
            table.add_row(str(i), r["subdomain"], r["ip"])

        console.print(table)
        console.print(f"\n[bold green]{len(results)}[/bold green] subdomain(s) found")

        if args.output:
            with open(args.output, "w") as f:
                for r in results:
                    f.write(f"{r['subdomain']}\t{r['ip']}\n")
            console.print(f"[dim]Results saved to {args.output}[/dim]")
    else:
        console.print("[bold red]No subdomains found[/bold red]")
