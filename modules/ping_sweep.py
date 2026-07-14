"""
Network Ping Sweep Module
Pings a range of hosts to discover live systems.
"""

import argparse
import subprocess
import sys
import platform
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn

console = Console()
results = []
lock = threading.Lock()

def ping_host(ip_str, timeout=1):
    try:
        param = "-n" if sys.platform == "win32" else "-c"
        timeout_param = "-w" if sys.platform == "win32" else "-W"
        result = subprocess.run(
            ["ping", param, "1", timeout_param, str(timeout), ip_str],
            capture_output=True, text=True, timeout=timeout + 2
        )
        if result.returncode == 0:
            # Extract response time
            import re
            time_match = re.search(r"time[<=](\d+)ms", result.stdout)
            latency = int(time_match.group(1)) if time_match else 0
            return {"ip": ip_str, "alive": True, "latency": latency}
    except:
        pass
    return {"ip": ip_str, "alive": False, "latency": 0}

def resolve_hostname(ip_str):
    try:
        return socket.gethostbyaddr(ip_str)[0]
    except:
        return "-"

def run(raw_args=None):
    import socket

    parser = argparse.ArgumentParser(description="Network Ping Sweep")
    parser.add_argument("-t", "--target", required=True, help="Target range (192.168.1.0/24 or 192.168.1.1-50)")
    parser.add_argument("--timeout", type=int, default=1, help="Ping timeout in seconds")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--dns", action="store_true", help="Resolve hostnames")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args(raw_args)

    # Parse target
    hosts = []
    target = args.target

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts())
        except:
            console.print(f"[bold red]Error:[/bold red] Invalid network '{target}'")
            sys.exit(1)
    elif "-" in target:
        parts = target.split(".")
        if len(parts) == 4 and "-" in parts[-1]:
            base = ".".join(parts[:3])
            start, end = parts[-1].split("-")
            for i in range(int(start), int(end) + 1):
                hosts.append(ipaddress.ip_address(f"{base}.{i}"))
        else:
            console.print(f"[bold red]Error:[/bold red] Invalid range '{target}'")
            sys.exit(1)
    else:
        try:
            hosts = [ipaddress.ip_address(target)]
        except:
            console.print(f"[bold red]Error:[/bold red] Invalid target '{target}'")
            sys.exit(1)

    console.print(f"[bold cyan]Sweeping {len(hosts)} host(s)...[/bold cyan]\n")

    alive_hosts = []

    with Progress(BarColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Pinging...", total=len(hosts))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(ping_host, str(host), args.timeout): host
                for host in hosts
            }
            for future in as_completed(futures):
                result = future.result()
                if result["alive"]:
                    alive_hosts.append(result)
                    console.print(f"  [green]+[/green] {result['ip']} ({result['latency']}ms)")
                progress.advance(task)

    # Sort by IP
    alive_hosts.sort(key=lambda x: ipaddress.ip_address(x["ip"]))

    if alive_hosts:
        table = Table(title=f"Live Hosts ({len(alive_hosts)}/{len(hosts)})", border_style="green", show_lines=True)
        table.add_column("#", style="dim")
        table.add_column("IP Address", style="bold cyan")
        table.add_column("Latency", style="yellow")

        if args.dns:
            table.add_column("Hostname", style="magenta")

        for i, h in enumerate(alive_hosts, 1):
            row = [str(i), h["ip"], f"{h['latency']}ms"]
            if args.dns:
                hostname = resolve_hostname(h["ip"])
                row.append(hostname)
            table.add_row(*row)

        console.print(table)

        # Stats
        latencies = [h["latency"] for h in alive_hosts if h["latency"] > 0]
        if latencies:
            avg = sum(latencies) / len(latencies)
            console.print(f"\n[bold]Stats:[/bold] Avg latency: {avg:.1f}ms, Min: {min(latencies)}ms, Max: {max(latencies)}ms")

        if args.output:
            with open(args.output, "w") as f:
                for h in alive_hosts:
                    f.write(f"{h['ip']}\t{h['latency']}ms\n")
            console.print(f"[dim]Results saved to {args.output}[/dim]")
    else:
        console.print("\n[bold red]No live hosts found[/bold red]")
