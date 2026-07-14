"""
Subdomain Takeover Checker Module
Checks if subdomains are vulnerable to takeover.
"""

import argparse
import sys
import socket
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

TAKEOVER_SERVICES = {
    "amazonaws.com": {"service": "AWS S3/CloudFront", "check": "NoSuchBucket"},
    "herokuapp.com": {"service": "Heroku", "check": "No such app"},
    "github.io": {"service": "GitHub Pages", "check": "There isn't a GitHub Pages site here"},
    "gitlab.io": {"service": "GitLab Pages", "check": "404"},
    "bitbucket.io": {"service": "Bitbucket", "check": "Repository not found"},
    "shopify.com": {"service": "Shopify", "check": "Sorry, this shop is currently unavailable"},
    "surge.sh": {"service": "Surge.sh", "check": "project not found"},
    "ghost.io": {"service": "Ghost", "check": "The thing you were looking for is no longer here"},
    "pantheon.io": {"service": "Pantheon", "check": "404 error unknown"},
    "tumblr.com": {"service": "Tumblr", "check": "Whatever you were looking for doesn't"},
    "zendesk.com": {"service": "Zendesk", "check": "Help Center Closed"},
    "helpjuice.com": {"service": "Helpjuice", "check": "We could not find what you're looking for"},
    "helpscoutdocs.com": {"service": "HelpScout", "check": "No settings were found"},
    "cargocollective.com": {"service": "Cargo Collective", "check": "If you're moving your domain"},
    "statuspage.io": {"service": "StatusPage", "check": "Better StatusPage"},
    "readme.io": {"service": "Readme", "check": "Project not found"},
    "cloudfront.net": {"service": "CloudFront", "check": "Bad request"},
    "s3.amazonaws.com": {"service": "AWS S3", "check": "NoSuchBucket"},
    "s3-website": {"service": "AWS S3", "check": "NoSuchBucket"},
    "azurewebsites.net": {"service": "Azure", "check": "404 Web Site not found"},
    "cloudapp.net": {"service": "Azure", "check": "404 Web Site not found"},
    "blob.core.windows.net": {"service": "Azure Blob", "check": "BlobNotFound"},
    "azure-api.net": {"service": "Azure API", "check": "Azure API Management"},
    "database.windows.net": {"service": "Azure SQL", "check": ""},
    "trafficmanager.net": {"service": "Azure Traffic Manager", "check": ""},
    "botframework.com": {"service": "Bot Framework", "check": ""},
    "asm.azureedge.net": {"service": "Azure CDN", "check": ""},
    "azurehdinsight.net": {"service": "Azure HDInsight", "check": ""},
    "azureedge.net": {"service": "Azure CDN", "check": ""},
    "azurecontainer.io": {"service": "Azure Container", "check": ""},
    "database.windows.net": {"service": "Azure SQL", "check": ""},
    "search.windows.net": {"service": "Azure Search", "check": ""},
    "azurecr.io": {"service": "Azure Container Registry", "check": ""},
    "redis.cache.windows.net": {"service": "Azure Redis", "check": ""},
    "azurehdinsight.net": {"service": "Azure HDInsight", "check": ""},
    "servicebus.windows.net": {"service": "Azure Service Bus", "check": ""},
    ".azurewebsites.net": {"service": "Azure Web Apps", "check": ""},
    "visualstudio.com": {"service": "Visual Studio", "check": ""},
    "dev.azure.com": {"service": "Azure DevOps", "check": ""},
    "onrender.com": {"service": "Render", "check": ""},
    "vercel.app": {"service": "Vercel", "check": ""},
    "netlify.app": {"service": "Netlify", "check": ""},
    "firebaseapp.com": {"service": "Firebase", "check": ""},
    "web.app": {"service": "Firebase Web App", "check": ""},
    "pages.dev": {"service": "Cloudflare Pages", "check": ""},
}

def check_subdomain_takeover(subdomain, timeout=5):
    results = []

    # Check if CNAME exists
    try:
        cname = socket.getaddrinfo(subdomain, None, socket.AF_INET, socket.SOCK_STREAM)
        ip = cname[0][4][0]
    except:
        return results

    # Check HTTP response
    for proto in ["https", "http"]:
        try:
            url = f"{proto}://{subdomain}"
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)

            # Check for known takeover signatures
            body = r.text[:10000].lower()

            for domain_key, info in TAKEOVER_SERVICES.items():
                if domain_key in subdomain.lower():
                    if info["check"].lower() in body:
                        results.append({
                            "subdomain": subdomain,
                            "ip": ip,
                            "service": info["service"],
                            "status": r.status_code,
                            "vulnerable": True
                        })
                        return results

            # Check for generic takeover indicators
            if r.status_code == 404:
                for domain_key, info in TAKEOVER_SERVICES.items():
                    if info["check"] and info["check"].lower() in body:
                        results.append({
                            "subdomain": subdomain,
                            "ip": ip,
                            "service": info["service"],
                            "status": r.status_code,
                            "vulnerable": True
                        })
                        return results

            results.append({
                "subdomain": subdomain,
                "ip": ip,
                "service": "Active",
                "status": r.status_code,
                "vulnerable": False
            })
            return results

        except requests.exceptions.ConnectionError as e:
            if "getaddrinfo failed" in str(e) or "Name or service not known" in str(e):
                results.append({
                    "subdomain": subdomain,
                    "ip": ip,
                    "service": "DNS resolves but no HTTP",
                    "status": "N/A",
                    "vulnerable": True
                })
                return results
        except:
            pass

    return results

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Subdomain Takeover Checker")
    parser.add_argument("-s", "--subdomains", nargs="+", required=True, help="Subdomains to check")
    parser.add_argument("-f", "--file", help="File with subdomains (one per line)")
    parser.add_argument("--timeout", type=float, default=5, help="Request timeout")

    args = parser.parse_args(raw_args)

    subdomains = list(args.subdomains)

    if args.file:
        if not os.path.isfile(args.file):
            console.print(f"[bold red]Error:[/bold red] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r") as f:
            subdomains.extend([line.strip() for line in f if line.strip()])

    console.print(f"[bold cyan]Checking {len(subdomains)} subdomain(s) for takeover...[/bold cyan]\n")

    all_results = []
    for sub in subdomains:
        console.print(f"  [dim]Checking {sub}...[/dim]", end="\r")
        results = check_subdomain_takeover(sub, args.timeout)
        all_results.extend(results)

    vulnerable = [r for r in all_results if r.get("vulnerable")]

    if all_results:
        table = Table(title="Subdomain Takeover Results", border_style="cyan", show_lines=True)
        table.add_column("Subdomain", style="bold")
        table.add_column("IP", style="cyan")
        table.add_column("Service", style="yellow")
        table.add_column("Status")
        table.add_column("Vulnerable")

        for r in all_results:
            vuln = "[bold red]YES[/bold red]" if r.get("vulnerable") else "[green]No[/green]"
            table.add_row(r["subdomain"], r["ip"], r["service"], str(r["status"]), vuln)

        console.print(table)

    if vulnerable:
        console.print(Panel(
            "\n".join(f"  - [red]{r['subdomain']}[/red] ({r['service']})" for r in vulnerable),
            title=f"[bold red]VULNERABLE - {len(vulnerable)} subdomain(s) at risk![/bold red]",
            border_style="red"
        ))
    else:
        console.print("\n[bold green]No subdomain takeover vulnerabilities found[/bold green]")
