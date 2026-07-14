"""
Email OSINT Module
Gathers information about an email address.
"""

import argparse
import re
import hashlib
import sys
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def check_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def get_gravatar(email, size=200):
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}?d=404&s={size}"

def check_disposable(email):
    disposable_domains = [
        "tempmail.com", "throwaway.email", "guerrillamail.com",
        "mailinator.com", "yopmail.com", "trashmail.com",
        "guerrillamailblock.com", "sharklasers.com", "grr.la",
        "dispostable.com", "maildrop.cc", "10minutemail.com",
        "temp-mail.org", "fakeinbox.com", "tempinbox.com",
        "mohmal.com", "burnermail.io", "getnada.com",
    ]
    domain = email.split("@")[1].lower()
    return domain in disposable_domains, domain

def check_breach(email):
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {"User-Agent": "CyberSec-Tools-v1.0"}
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            return True, r.json()
        elif r.status_code == 404:
            return False, []
    except:
        return None, "API unavailable"
    return None, "API unavailable"

def check_emailrep(email):
    try:
        headers = {"User-Agent": "CyberSec-Tools-v1.0"}
        r = requests.get(f"https://emailrep.io/{email}", headers=headers, timeout=5)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Email OSINT")
    parser.add_argument("-e", "--email", required=True, help="Target email address")
    parser.add_argument("--no-gravatar", action="store_true", help="Skip Gravatar check")
    parser.add_argument("--breach", action="store_true", help="Check for breaches")

    args = parser.parse_args(raw_args)

    email = args.email.lower().strip()

    if not check_email(email):
        console.print(f"[bold red]Error:[/bold red] Invalid email format: {email}")
        sys.exit(1)

    username = email.split("@")[0]
    domain = email.split("@")[1]

    console.print(Panel(
        f"[bold cyan]Email:[/bold cyan] {email}\n"
        f"[bold cyan]Username:[/bold cyan] {username}\n"
        f"[bold cyan]Domain:[/bold cyan] {domain}",
        title="[bold]Email OSINT Analysis[/bold]", border_style="cyan"
    ))

    # Disposable check
    is_disposable, disp_domain = check_disposable(email)
    if is_disposable:
        console.print(f"[bold red]WARNING:[/bold red] Disposable email provider: {disp_domain}")
    else:
        console.print(f"[green]Email provider appears to be legitimate[/green]")

    # Gravatar
    if not args.no_gravatar:
        gravatar_url = get_gravatar(email)
        try:
            r = requests.get(gravatar_url, timeout=5)
            if r.status_code == 200:
                console.print(f"[yellow]Gravatar found![/yellow] URL: {gravatar_url}")
            else:
                console.print(f"[dim]No Gravatar found for this email[/dim]")
        except:
            console.print(f"[dim]Could not check Gravatar[/dim]")

    # EmailRep
    console.print("\n[bold cyan]Querying EmailRep...[/bold cyan]")
    rep = check_emailrep(email)
    if rep:
        table = Table(title="EmailRep Analysis", border_style="cyan", show_lines=True)
        table.add_column("Field", style="bold")
        table.add_column("Value")

        table.add_row("Reputation", str(rep.get("reputation", "N/A")))
        table.add_row("Suspicious", str(rep.get("suspicious", "N/A")))
        table.add_row("References", str(rep.get("references", "N/A")))

        details = rep.get("details", {})
        if details:
            table.add_row("Blacklisted", str(details.get("blacklisted", "N/A")))
            table.add_row("Malicious Activity", str(details.get("malicious_activity", "N/A")))
            table.add_row("Credentials Leaked", str(details.get("credentials_leaked", "N/A")))
            table.add_row("Data Breach", str(details.get("data_breach", "N/A")))
            table.add_row("First Seen", str(details.get("first_seen", "N/A")))
            table.add_row("Last Seen", str(details.get("last_seen", "N/A")))
            table.add_row("Spam", str(details.get("spam", "N/A")))
            table.add_row("Free Provider", str(details.get("free_provider", "N/A")))
            table.add_row("Disposable", str(details.get("disposable", "N/A")))
            table.add_row("Deliverable", str(details.get("deliverable", "N/A")))

        console.print(table)
    else:
        console.print("[dim]EmailRep data unavailable[/dim]")

    # Breach check
    if args.breach:
        console.print("\n[bold cyan]Checking breaches...[/bold cyan]")
        has_breach, breach_data = check_breach(email)
        if has_breach is True:
            console.print(f"[bold red]FOUND in data breaches![/bold red]")
            if isinstance(breach_data, list):
                for b in breach_data[:10]:
                    console.print(f"  - {b.get('Name', 'Unknown')}: {b.get('BreachDate', 'Unknown')}")
        elif has_breach is False:
            console.print("[green]Not found in known data breaches[/green]")
        else:
            console.print(f"[dim]{breach_data}[/dim]")

    # Email format variations
    console.print("\n[bold]Email Format Variations:[/bold]")
    console.print(f"  Username: {username}")
    console.print(f"  Full: {email}")
    console.print(f"  MD5 Hash: {hashlib.md5(email.encode()).hexdigest()}")
    console.print(f"  SHA256: {hashlib.sha256(email.encode()).hexdigest()[:32]}...")
