"""
SSL/TLS Checker Module
Analyzes SSL/TLS certificates, protocols, and cipher suites.
"""

import argparse
import ssl
import socket
import sys
import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
STRONG_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "CBC", "RC2", "IDEA"
]

def get_cert_info(hostname, port=443, timeout=10):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(timeout)
            s.connect((hostname, port))
            cert = s.getpeercert()
            cipher = s.cipher()
            version = s.version()
            return cert, cipher, version, None
    except Exception as e:
        return None, None, None, str(e)

def check_protocols(hostname, port=443, timeout=5):
    results = []
    for proto_name in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            proto_map = {
                "SSLv2": getattr(ssl, "PROTOCOL_TLSv1", None),
                "SSLv3": getattr(ssl, "PROTOCOL_TLSv1", None),
                "TLSv1": getattr(ssl, "PROTOCOL_TLSv1", None),
                "TLSv1.1": getattr(ssl, "PROTOCOL_TLSv1", None),
                "TLSv1.2": ssl.PROTOCOL_TLS,
                "TLSv1.3": ssl.PROTOCOL_TLS,
            }

            if proto_name in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
                    min_ver = {
                        "SSLv2": ssl.TLSVersion.SSLv2 if hasattr(ssl.TLSVersion, 'SSLv2') else None,
                        "SSLv3": ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, 'SSLv3') else None,
                        "TLSv1": ssl.TLSVersion.TLSv1,
                        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                    }.get(proto_name)
                    if min_ver:
                        ctx.minimum_version = min_ver
                        ctx.maximum_version = min_ver
                        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                            s.settimeout(timeout)
                            s.connect((hostname, port))
                            results.append({"protocol": proto_name, "supported": True})
                            continue
                except:
                    pass
                results.append({"protocol": proto_name, "supported": False})
            else:
                ctx = ssl.create_default_context()
                min_ver = {
                    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
                    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
                }.get(proto_name)
                if min_ver:
                    ctx.minimum_version = min_ver
                    try:
                        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                            s.settimeout(timeout)
                            s.connect((hostname, port))
                            results.append({"protocol": proto_name, "supported": True})
                    except:
                        results.append({"protocol": proto_name, "supported": False})
        except:
            results.append({"protocol": proto_name, "supported": False})
    return results

def parse_cert(cert):
    info = {}
    if not cert:
        return info

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))

    info["subject_cn"] = subject.get("commonName", "N/A")
    info["subject_o"] = subject.get("organizationName", "N/A")
    info["subject_c"] = subject.get("countryName", "N/A")

    info["issuer_cn"] = issuer.get("commonName", "N/A")
    info["issuer_o"] = issuer.get("organizationName", "N/A")

    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")

    try:
        info["valid_from"] = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        info["valid_to"] = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        info["days_left"] = (info["valid_to"] - datetime.datetime.utcnow()).days
    except:
        info["valid_from"] = not_before
        info["valid_to"] = not_after
        info["days_left"] = "N/A"

    info["serial"] = cert.get("serialNumber", "N/A")
    info["san"] = []
    for ext in cert.get("subjectAltName", []):
        info["san"].append(ext[1])

    return info

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="SSL/TLS Certificate Analyzer")
    parser.add_argument("-t", "--target", required=True, help="Target hostname")
    parser.add_argument("-p", "--port", type=int, default=443, help="SSL port (default: 443)")
    parser.add_argument("--check-protocols", action="store_true", help="Test protocol support")

    args = parser.parse_args(raw_args)

    hostname = args.target
    console.print(f"[bold cyan]Analyzing SSL/TLS for:[/bold cyan] {hostname}:{args.port}\n")

    cert, cipher, version, error = get_cert_info(hostname, args.port)

    if error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        sys.exit(1)

    info = parse_cert(cert)

    # Certificate info
    days_left = info.get("days_left", "N/A")
    if isinstance(days_left, int):
        if days_left < 0:
            days_color = "red"
            days_str = f"EXPIRED ({abs(days_left)} days ago)"
        elif days_left < 30:
            days_color = "red"
            days_str = f"{days_left} days"
        elif days_left < 90:
            days_color = "yellow"
            days_str = f"{days_left} days"
        else:
            days_color = "green"
            days_str = f"{days_left} days"
    else:
        days_color = "dim"
        days_str = str(days_left)

    cert_table = Table(title="Certificate Information", border_style="cyan", show_lines=True)
    cert_table.add_column("Field", style="bold", min_width=18)
    cert_table.add_column("Value")

    cert_table.add_row("Subject CN", info.get("subject_cn", "N/A"))
    cert_table.add_row("Subject Org", info.get("subject_o", "N/A"))
    cert_table.add_row("Subject Country", info.get("subject_c", "N/A"))
    cert_table.add_row("Issuer CN", info.get("issuer_cn", "N/A"))
    cert_table.add_row("Issuer Org", info.get("issuer_o", "N/A"))
    cert_table.add_row("Valid From", str(info.get("valid_from", "N/A")))
    cert_table.add_row("Valid To", str(info.get("valid_to", "N/A")))
    cert_table.add_row("Days Left", f"[{days_color}]{days_str}[/{days_color}]")
    cert_table.add_row("Serial", info.get("serial", "N/A"))
    cert_table.add_row("SAN Count", str(len(info.get("san", []))))
    cert_table.add_row("TLS Version", version or "N/A")
    cert_table.add_row("Cipher", cipher[0] if cipher else "N/A")
    cert_table.add_row("Cipher Protocol", cipher[1] if cipher else "N/A")
    cert_table.add_row("Cipher Bits", str(cipher[2]) if cipher else "N/A")

    console.print(cert_table)

    # SAN list
    san_list = info.get("san", [])
    if san_list:
        console.print(f"\n[bold]Subject Alternative Names ({len(san_list)}):[/bold]")
        for san in san_list[:20]:
            console.print(f"  - {san}")
        if len(san_list) > 20:
            console.print(f"  [dim]... and {len(san_list) - 20} more[/dim]")

    # Cipher analysis
    if cipher:
        cipher_name = cipher[0]
        is_weak = any(w.lower() in cipher_name.lower() for w in WEAK_CIPHERS)
        if is_weak:
            console.print(f"\n[bold red]WEAK CIPHER:[/bold red] {cipher_name}")
        else:
            console.print(f"\n[bold green]Cipher appears strong:[/bold green] {cipher_name}")

    # Protocol check
    if args.check_protocols:
        console.print(f"\n[bold cyan]Checking protocol support...[/bold cyan]")
        protocols = check_protocols(hostname, args.port)
        proto_table = Table(title="Protocol Support", border_style="cyan")
        proto_table.add_column("Protocol", style="bold")
        proto_table.add_column("Supported")
        proto_table.add_column("Security")

        for p in protocols:
            supported = "Yes" if p["supported"] else "No"
            if p["supported"]:
                if p["protocol"] in WEAK_PROTOCOLS:
                    security = "[bold red]WEAK - Should be disabled[/bold red]"
                else:
                    security = "[bold green]OK[/bold green]"
            else:
                security = "[dim]N/A[/dim]"
            proto_table.add_row(p["protocol"], supported, security)

        console.print(proto_table)

    # Summary
    issues = []
    if isinstance(days_left, int):
        if days_left < 0:
            issues.append("Certificate EXPIRED")
        elif days_left < 30:
            issues.append(f"Certificate expires in {days_left} days")

    if cipher and any(w.lower() in cipher[0].lower() for w in WEAK_CIPHERS):
        issues.append("Weak cipher suite detected")

    if issues:
        console.print(Panel(
            "\n".join(f"  - [red]{i}[/red]" for i in issues),
            title="[bold red]Issues Found[/bold red]", border_style="red"
        ))
    else:
        console.print("[bold green]No critical SSL/TLS issues detected[/bold green]")
