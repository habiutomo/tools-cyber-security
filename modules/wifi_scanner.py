"""
WiFi Scanner Module
Scans nearby WiFi networks using system commands.
"""

import argparse
import sys
import subprocess
import re
import platform
from rich.console import Console
from rich.table import Table

console = Console()

def scan_windows():
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            console.print("[bold red]Error:[/bold red] Make sure WiFi adapter is enabled")
            return []

        networks = []
        current = {}

        for line in result.stdout.split("\n"):
            line = line.strip()
            if "SSID" in line and "BSSID" not in line:
                if current and current.get("ssid"):
                    networks.append(current)
                ssid = line.split(":", 1)[1].strip() if ":" in line else ""
                current = {"ssid": ssid, "signal": "", "auth": "", "encryption": "", "channel": ""}
            elif "Signal" in line:
                current["signal"] = line.split(":", 1)[1].strip()
            elif "Authentication" in line:
                current["auth"] = line.split(":", 1)[1].strip()
            elif "Encryption" in line:
                current["encryption"] = line.split(":", 1)[1].strip()
            elif "Channel" in line:
                current["channel"] = line.split(":", 1)[1].strip()

        if current and current.get("ssid"):
            networks.append(current)

        return networks

    except FileNotFoundError:
        console.print("[bold red]Error:[/bold red] netsh command not found")
        return []
    except subprocess.TimeoutExpired:
        console.print("[bold red]Error:[/bold red] Scan timed out")
        return []

def scan_linux():
    try:
        result = subprocess.run(
            ["iwlist", "wlan0", "scan"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            # Try with sudo
            result = subprocess.run(
                ["sudo", "iwlist", "wlan0", "scan"],
                capture_output=True, text=True, timeout=15
            )

        networks = []
        current = {}

        for line in result.stdout.split("\n"):
            line = line.strip()
            if "ESSID" in line:
                if current and current.get("ssid"):
                    networks.append(current)
                ssid = line.split('"')[1] if '"' in line else ""
                current = {"ssid": ssid, "signal": "", "auth": "", "encryption": "", "channel": ""}
            elif "Signal level" in line:
                match = re.search(r"Signal level=(-?\d+)", line)
                if match:
                    signal = int(match.group(1))
                    current["signal"] = f"{max(0, min(100, signal + 100))}%"
            elif "Authentication suites" in line or "Key Management" in line:
                current["auth"] = line.split(":")[-1].strip()
            elif "Encryption key" in line:
                current["encryption"] = "on" if "on" in line.lower() else "off"
            elif "Channel:" in line:
                current["channel"] = line.split(":")[-1].strip()

        if current and current.get("ssid"):
            networks.append(current)

        return networks

    except FileNotFoundError:
        console.print("[bold red]Error:[/bold red] iwlist not found. Install wireless-tools")
        return []
    except subprocess.TimeoutExpired:
        console.print("[bold red]Error:[/bold red] Scan timed out")
        return []

def signal_bar(signal_str):
    try:
        pct = int(signal_str.replace("%", ""))
        bars = pct // 20
        return "#" * bars + "-" * (5 - bars) + f" {pct}%"
    except:
        return signal_str

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="WiFi Scanner")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--show-hidden", action="store_true", help="Show hidden networks")

    args = parser.parse_args(raw_args)

    console.print("[bold cyan]Scanning WiFi networks...[/bold cyan]\n")

    system = platform.system()
    if system == "Windows":
        networks = scan_windows()
    elif system == "Linux":
        networks = scan_linux()
    else:
        console.print(f"[bold red]Error:[/bold red] WiFi scanning not supported on {system}")
        sys.exit(1)

    if not networks:
        console.print("[bold red]No networks found[/bold red]")
        sys.exit(1)

    # Filter hidden
    if not args.show_hidden:
        networks = [n for n in networks if n["ssid"]]

    # Remove duplicates
    seen = set()
    unique = []
    for n in networks:
        key = n["ssid"]
        if key not in seen:
            seen.add(key)
            unique.append(n)
    networks = sorted(unique, key=lambda x: x["ssid"])

    table = Table(title=f"WiFi Networks ({len(networks)} found)", border_style="green", show_lines=True)
    table.add_column("#", style="dim")
    table.add_column("SSID", style="bold cyan")
    table.add_column("Signal", style="green")
    table.add_column("Channel", style="yellow")
    table.add_column("Auth", style="magenta")
    table.add_column("Encryption", style="white")

    for i, n in enumerate(networks, 1):
        auth = n.get("auth", "Unknown")
        open_network = "Open" in auth or auth == "None" or n.get("encryption", "").lower() == "off"
        auth_style = "red" if open_network else "magenta"

        table.add_row(
            str(i),
            n["ssid"],
            signal_bar(n.get("signal", "")),
            n.get("channel", "?"),
            f"[{auth_style}]{auth}[/{auth_style}]",
            n.get("encryption", "?")
        )

    console.print(table)

    # Security warnings
    open_nets = [n for n in networks if "Open" in n.get("auth", "") or n.get("encryption", "").lower() == "off"]
    if open_nets:
        console.print(f"\n[bold yellow]WARNING:[/bold yellow] {len(open_nets)} open (unencrypted) network(s) detected:")
        for n in open_nets:
            console.print(f"  - [red]{n['ssid']}[/red]")

    if args.output:
        with open(args.output, "w") as f:
            for n in networks:
                f.write(f"{n['ssid']}\t{n.get('signal', '')}\t{n.get('channel', '')}\t{n.get('auth', '')}\n")
        console.print(f"[dim]Results saved to {args.output}[/dim]")
