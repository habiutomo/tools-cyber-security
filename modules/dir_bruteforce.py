"""
Directory Brute Force Module
Brute forces directories and files on web servers.
"""

import argparse
import sys
import os
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from urllib3.exceptions import InsecureRequestWarning

console = Console()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DEFAULT_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "cpanel", "whm", "webmail", "mail",
    "api", "v1", "v2", "v3", "graphql", "swagger", "docs",
    "backup", "backups", "bak", "old", "temp", "tmp",
    "config", "configuration", "settings", "env", ".env",
    "database", "db", "sql", "dump", "export", "import",
    "git", ".git", ".git/config", ".gitignore", "svn", ".svn",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "favicon.ico",
    ".htaccess", ".htpasswd", "web.config", "server-status",
    "debug", "test", "testing", "dev", "development", "staging",
    "uploads", "upload", "files", "media", "images", "img", "assets",
    "static", "css", "js", "scripts", "fonts",
    "blog", "news", "forum", "comments",
    "user", "users", "account", "accounts", "profile",
    "dashboard", "panel", "console", "manage",
    "status", "health", "ping", "info", "version",
    "log", "logs", "error", "errors",
    "register", "signup", "signin", "reset", "forgot",
    "search", "find", "query",
    "download", "downloads", "upload",
    "js", "json", "xml", "csv", "txt", "pdf",
    ".well-known", ".well-known/security.txt", "security.txt",
    "readme", "README.md", "LICENSE", "CHANGELOG",
]

def check_path(base_url, path, timeout, follow_redirects, allow_codes):
    url = urljoin(base_url, path)
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                        allow_redirects=follow_redirects)
        status = r.status_code
        size = len(r.content)
        redirect = r.url if r.url != url else ""
        if status in allow_codes or (200 <= status < 400) or status in [401, 403]:
            return {"path": path, "status": status, "size": size, "redirect": redirect}
    except:
        pass
    return None

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Directory Brute Force")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. http://example.com/)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=5, help="Request timeout")
    parser.add_argument("--follow", action="store_true", help="Follow redirects")
    parser.add_argument("--codes", default="200,201,301,302,307,401,403,405",
                       help="HTTP codes to show (comma-separated)")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args(raw_args)

    base_url = args.url if args.url.endswith("/") else args.url + "/"

    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            console.print(f"[bold red]Error:[/bold red] Wordlist not found: {args.wordlist}")
            sys.exit(1)
        with open(args.wordlist, "r", errors="ignore") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    else:
        wordlist = DEFAULT_DIRS

    allow_codes = set(int(c.strip()) for c in args.codes.split(","))

    console.print(f"[bold cyan]Target:[/bold cyan] {base_url}")
    console.print(f"[bold cyan]Wordlist:[/bold cyan] {len(wordlist)} entries")
    console.print(f"[bold cyan]Threads:[/bold cyan] {args.threads}\n")

    results = []

    with Progress(BarColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Brute forcing...", total=len(wordlist))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(check_path, base_url, path, args.timeout, args.follow, allow_codes): path
                for path in wordlist
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    size_str = f"{result['size']}B"
                    console.print(f"  [green]{result['status']}[/green] {result['path']} ({size_str})")
                progress.advance(task)

    if results:
        results.sort(key=lambda x: (x["status"], x["path"]))

        table = Table(title=f"Found Paths on {base_url}", border_style="green", show_lines=True)
        table.add_column("Status", style="bold")
        table.add_column("Path", style="cyan")
        table.add_column("Size", style="yellow")
        table.add_column("Redirect", style="dim", max_width=50)

        for r in results:
            status_color = "green" if 200 <= r["status"] < 300 else "yellow" if 300 <= r["status"] < 400 else "red"
            size_str = f"{r['size']:,} B"
            table.add_row(
                f"[{status_color}]{r['status']}[/{status_color}]",
                r["path"], size_str, r["redirect"][:50]
            )

        console.print(table)
        console.print(f"\n[bold green]{len(results)}[/bold green] path(s) found")

        if args.output:
            with open(args.output, "w") as f:
                for r in results:
                    f.write(f"{r['status']}\t{r['path']}\t{r['size']}\t{r['redirect']}\n")
            console.print(f"[dim]Results saved to {args.output}[/dim]")
    else:
        console.print("[bold red]No paths found[/bold red]")
