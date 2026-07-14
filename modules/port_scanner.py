"""
Port Scanner Module
Scans open ports on a target host with banner grabbing.
"""

import socket
import argparse
import threading
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.panel import Panel

console = Console()

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Proxy",
    9200: "Elasticsearch", 27017: "MongoDB"
}

results = []
lock = threading.Lock()

def grab_banner(ip, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            s.send(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except:
            banner = ""
        s.close()
        return banner
    except:
        return ""

def scan_port(ip, port, timeout, grab_banners):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(ip, port, timeout) if grab_banners else ""
            service = COMMON_PORTS.get(port, "Unknown")
            with lock:
                results.append({"port": port, "service": service, "banner": banner})
        s.close()
    except:
        pass

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g. 1-1024, 80,443)")
    parser.add_argument("--top", type=int, default=0, help="Scan top N common ports")
    parser.add_argument("-T", "--timeout", type=float, default=1.0, help="Connection timeout (seconds)")
    parser.add_argument("-b", "--banner", action="store_true", help="Grab banners from open ports")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args(raw_args)

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        console.print(f"[bold red]Error:[/bold red] Cannot resolve '{args.target}'")
        sys.exit(1)

    if args.top > 0:
        ports = sorted(COMMON_PORTS.keys())[:args.top]
    else:
        ports = []
        for part in args.ports.split(","):
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))

    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {args.target} ({target_ip})\n"
        f"[bold cyan]Ports:[/bold cyan] {len(ports)} port(s)\n"
        f"[bold cyan]Timeout:[/bold cyan] {args.timeout}s\n"
        f"[bold cyan]Banner Grabbing:[/bold cyan] {'Yes' if args.banner else 'No'}",
        title="[bold]Port Scanner[/bold]", border_style="yellow"
    ))

    global results
    results = []

    max_threads = min(100, len(ports))
    threads = []

    with Progress(BarColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Scanning...", total=len(ports))
        sem = threading.Semaphore(max_threads)

        def worker(port):
            sem.acquire()
            scan_port(target_ip, port, args.timeout, args.banner)
            progress.advance(task)
            sem.release()

        for port in ports:
            t = threading.Thread(target=worker, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    results.sort(key=lambda x: x["port"])

    if results:
        table = Table(title=f"Open Ports on {args.target}", border_style="green")
        table.add_column("Port", style="bold cyan")
        table.add_column("State", style="bold green")
        table.add_column("Service", style="yellow")
        if args.banner:
            table.add_column("Banner", style="dim")

        for r in results:
            row = [str(r["port"]), "OPEN", r["service"]]
            if args.banner:
                row.append(r["banner"][:80])
            table.add_row(*row)

        console.print(table)
        console.print(f"\n[bold green]{len(results)}[/bold green] open port(s) found")

        if args.output:
            with open(args.output, "w") as f:
                for r in results:
                    line = f"{r['port']}\tOPEN\t{r['service']}"
                    if args.banner:
                        line += f"\t{r['banner']}"
                    f.write(line + "\n")
            console.print(f"[dim]Results saved to {args.output}[/dim]")
    else:
        console.print("[bold red]No open ports found[/bold red]")
