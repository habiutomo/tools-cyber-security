"""
Host Discovery Module
Discovers live hosts in a network range using ICMP/TCP.
"""

import socket
import argparse
import threading
import subprocess
import sys
import ipaddress
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn

console = Console()
results = []
lock = threading.Lock()

def ping_host(ip_str):
    try:
        param = "-n" if sys.platform == "win32" else "-c"
        timeout_param = "-w" if sys.platform == "win32" else "-W"
        result = subprocess.run(
            ["ping", param, "1", timeout_param, "1", ip_str],
            capture_output=True, text=True, timeout=3
        )
        return result.returncode == 0
    except:
        return False

def tcp_check(ip_str, port=80, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((str(ip_str), port))
        s.close()
        return result == 0
    except:
        return False

def resolve_hostname(ip_str):
    try:
        return socket.gethostbyaddr(str(ip_str))[0]
    except:
        return "-"

def scan_host(ip_str, use_icmp, tcp_port):
    ip_str = str(ip_str)
    alive = False
    if use_icmp:
        alive = ping_host(ip_str)
    if not alive:
        alive = tcp_check(ip_str, tcp_port)
    if alive:
        hostname = resolve_hostname(ip_str)
        with lock:
            results.append({"ip": ip_str, "hostname": hostname})

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Host Discovery")
    parser.add_argument("-t", "--target", required=True, help="Target network (e.g. 192.168.1.0/24 or 192.168.1.1-50)")
    parser.add_argument("-m", "--method", choices=["icmp", "tcp", "both"], default="both", help="Discovery method")
    parser.add_argument("--port", type=int, default=80, help="TCP port for discovery (default: 80)")
    parser.add_argument("-T", "--timeout", type=float, default=1.0, help="Timeout per host")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args(raw_args)

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

    use_icmp = args.method in ["icmp", "both"]
    use_tcp = args.method in ["tcp", "both"]

    console.print(f"[bold cyan]Scanning {len(hosts)} host(s)...[/bold cyan]")
    global results
    results = []

    max_threads = min(50, len(hosts))
    sem = threading.Semaphore(max_threads)

    with Progress(BarColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Discovering hosts...", total=len(hosts))

        def worker(host):
            sem.acquire()
            if use_icmp and use_tcp:
                alive = ping_host(str(host))
                if not alive:
                    alive = tcp_check(str(host), args.port)
                if alive:
                    hostname = resolve_hostname(str(host))
                    with lock:
                        results.append({"ip": str(host), "hostname": hostname})
            else:
                scan_host(host, use_icmp, args.port)
            progress.advance(task)
            sem.release()

        threads = []
        for host in hosts:
            t = threading.Thread(target=worker, args=(host,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    if results:
        table = Table(title="Live Hosts", border_style="green")
        table.add_column("#", style="dim")
        table.add_column("IP Address", style="bold cyan")
        table.add_column("Hostname", style="yellow")

        for i, r in enumerate(sorted(results, key=lambda x: ipaddress.ip_address(x["ip"])), 1):
            table.add_row(str(i), r["ip"], r["hostname"])

        console.print(table)
        console.print(f"\n[bold green]{len(results)}[/bold green] host(s) found")

        if args.output:
            with open(args.output, "w") as f:
                for r in results:
                    f.write(f"{r['ip']}\t{r['hostname']}\n")
            console.print(f"[dim]Results saved to {args.output}[/dim]")
    else:
        console.print("[bold red]No live hosts found[/bold red]")
