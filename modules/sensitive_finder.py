"""
Sensitive File Finder Module
Discovers sensitive files and directories on web servers.
"""

import argparse
import sys
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn

console = Console()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SENSITIVE_PATHS = [
    # Version control
    ".git/HEAD", ".git/config", ".gitignore", ".git/config.json",
    ".svn/entries", ".svn/wc.db",
    ".hg/hgrc", ".bzr/README",

    # Environment & config
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.bak", ".env.old", ".env.backup",
    "config.php", "config.php.bak", "wp-config.php.bak",
    "configuration.php", "settings.php", "config.yml",
    "config.json", "config.yaml", "config.ini", "config.conf",
    "web.config", "application.yml", "application.properties",
    "database.yml", "db.php", "db.php.bak",
    "credentials.json", "secrets.json", "secrets.yml",

    # Backup files
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "backup.sql.gz", "dump.sql", "dump.sql.gz",
    "db.sql", "database.sql", "data.sql",
    "site.tar.gz", "website.zip", "www.zip", "html.zip",
    "archive.zip", "old.zip",
    "backup.php", "backup.bak",

    # Admin panels
    "admin", "admin.php", "admin/", "administrator",
    "wp-admin", "cpanel", "phpmyadmin", "phpMyAdmin",
    "pma", "myadmin", "webadmin",

    # Logs
    "error.log", "access.log", "debug.log", "application.log",
    "server.log", "app.log", "laravel.log", "php_errors.log",
    "log.txt", "error_log", "access_log",

    # Info disclosure
    "server-status", "server-info", "phpinfo.php", "info.php",
    "test.php", "php-test.php",
    "readme.html", "README.md", "README.txt", "README",
    "LICENSE", "LICENSE.txt", "CHANGELOG", "CHANGELOG.md",
    "TODO", "TODO.md", "CONTRIBUTING.md",

    # Sensitive directories
    ".well-known/", ".well-known/security.txt",
    ".DS_Store", "Thumbs.db",
    "elmah.axd", "trace.axd",

    # API & docs
    "api/", "api/v1/", "api/v2/", "swagger", "swagger-ui",
    "api-docs", "swagger.json", "openapi.json",
    "graphql", ".graphql",

    # Temp & misc
    "tmp/", "temp/", "cache/",
    "debug/", "test/", "staging/",
    "install.php", "setup.php", "update.php",
    "wp-config.php", "wp-config.php.dist",
    "htaccess", ".htaccess", ".htpasswd",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "sitemaps.xml", "sitemap_index.xml",
]

def check_path(base_url, path, timeout, follow_redirects):
    url = urljoin(base_url, path)
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                        allow_redirects=follow_redirects,
                        headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code in [200, 301, 302, 307, 401, 403]:
            return {
                "path": path,
                "status": r.status_code,
                "size": len(r.content),
                "type": r.headers.get("Content-Type", "")[:30]
            }
    except:
        pass
    return None

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Sensitive File Finder")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=15, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=5, help="Request timeout")
    parser.add_argument("--follow", action="store_true", help="Follow redirects")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args(raw_args)

    base_url = args.url if args.url.endswith("/") else args.url + "/"

    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            console.print(f"[bold red]Error:[/bold red] Wordlist not found: {args.wordlist}")
            sys.exit(1)
        with open(args.wordlist, "r", errors="ignore") as f:
            paths = [line.strip() for line in f if line.strip()]
    else:
        paths = SENSITIVE_PATHS

    console.print(f"[bold cyan]Target:[/bold cyan] {base_url}")
    console.print(f"[bold cyan]Paths to check:[/bold cyan] {len(paths)}")
    console.print(f"[bold cyan]Threads:[/bold cyan] {args.threads}\n")

    results = []

    with Progress(BarColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Scanning...", total=len(paths))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(check_path, base_url, path, args.timeout, args.follow): path
                for path in paths
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    status_color = "green" if result["status"] == 200 else "yellow"
                    console.print(f"  [{status_color}]{result['status']}[/{status_color}] {result['path']} ({result['size']}B)")
                progress.advance(task)

    if results:
        results.sort(key=lambda x: x["path"])

        table = Table(title=f"Sensitive Files Found ({len(results)})", border_style="red", show_lines=True)
        table.add_column("Status", style="bold")
        table.add_column("Path", style="cyan")
        table.add_column("Size", style="yellow")
        table.add_column("Type", style="dim")

        for r in results:
            status_color = "red" if r["status"] == 200 else "yellow"
            table.add_row(
                f"[{status_color}]{r['status']}[/{status_color}]",
                r["path"],
                f"{r['size']:,} B",
                r["type"]
            )

        console.print(table)

        critical = [r for r in results if r["status"] == 200]
        if critical:
            console.print(f"\n[bold red]CRITICAL:[/bold red] {len(critical)} path(s) returned 200 OK")

        if args.output:
            with open(args.output, "w") as f:
                for r in results:
                    f.write(f"{r['status']}\t{r['path']}\t{r['size']}\n")
            console.print(f"[dim]Results saved to {args.output}[/dim]")
    else:
        console.print("[bold green]No sensitive files found[/bold green]")
