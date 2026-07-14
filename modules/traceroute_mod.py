"""
Traceroute Module
Traces network path to a destination with latency and geo info.
"""

import argparse
import subprocess
import sys
import re
import platform
from rich.console import Console
from rich.table import Table

console = Console()

def traceroute(target, max_hops=30, timeout=3):
    system = platform.system()
    if system == "Windows":
        cmd = ["tracert", "-d", "-w", str(timeout * 1000), "-h", str(max_hops), target]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * timeout * 2)
        return result.stdout, result.returncode
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] traceroute not found")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        return "", 1

def parse_traceroute(output, system):
    hops = []
    for line in output.split("\n"):
        line = line.strip()
        if not line or line.startswith("Tracing") or line.startswith("Over a") or "Trace complete" in line:
            continue

        # Windows format: "  1     1 ms     1 ms     1 ms  192.168.1.1"
        win_match = re.match(r'\s*(\d+)\s+(.+)', line)
        if win_match:
            hop_num = int(win_match.group(1))
            rest = win_match.group(2)

            times = re.findall(r'(\d+)\s*ms', rest)
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', rest)
            timeout_match = re.search(r'(\*|Request timed out)', rest, re.IGNORECASE)

            if ip_match:
                ip = ip_match.group(1)
                latencies = [int(t) for t in times] if times else [0]
                avg = sum(latencies) / len(latencies) if latencies else 0
                hops.append({
                    "hop": hop_num,
                    "ip": ip,
                    "avg_ms": round(avg, 1),
                    "min_ms": min(latencies) if latencies else 0,
                    "max_ms": max(latencies) if latencies else 0,
                    "lost": False
                })
            elif timeout_match:
                hops.append({
                    "hop": hop_num,
                    "ip": "*",
                    "avg_ms": 0,
                    "min_ms": 0,
                    "max_ms": 0,
                    "lost": True
                })

    return hops

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Traceroute")
    parser.add_argument("-t", "--target", required=True, help="Target hostname or IP")
    parser.add_argument("--max-hops", type=int, default=30, help="Maximum hops (default: 30)")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout per hop in seconds")
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args(raw_args)

    console.print(f"[bold cyan]Traceroute to:[/bold cyan] {args.target} (max {args.max_hops} hops)\n")

    output, returncode = traceroute(args.target, args.max_hops, args.timeout)

    if not output:
        console.print("[bold red]No traceroute data received[/bold red]")
        sys.exit(1)

    hops = parse_traceroute(output, platform.system())

    if not hops:
        console.print("[dim]Raw output:[/dim]")
        console.print(output)
        sys.exit(0)

    table = Table(title=f"Traceroute to {args.target}", border_style="green", show_lines=True)
    table.add_column("Hop", style="bold")
    table.add_column("IP Address", style="cyan")
    table.add_column("Avg (ms)", style="yellow")
    table.add_column("Min (ms)", style="green")
    table.add_column("Max (ms)", style="red")

    for h in hops:
        if h["lost"]:
            table.add_row(str(h["hop"]), "[dim]*[/dim]", "[dim]---[/dim]", "[dim]---[/dim]", "[dim]---[/dim]")
        else:
            avg_color = "green" if h["avg_ms"] < 50 else "yellow" if h["avg_ms"] < 150 else "red"
            table.add_row(
                str(h["hop"]),
                h["ip"],
                f"[{avg_color}]{h['avg_ms']}[/{avg_color}]",
                str(h["min_ms"]),
                str(h["max_ms"])
            )

    console.print(table)

    total_hops = len([h for h in hops if not h["lost"]])
    lost_hops = len([h for h in hops if h["lost"]])
    console.print(f"\n[bold]{total_hops}[/bold] hops completed, [bold red]{lost_hops}[/bold red] packet loss")

    if args.output:
        with open(args.output, "w") as f:
            for h in hops:
                if not h["lost"]:
                    f.write(f"{h['hop']}\t{h['ip']}\t{h['avg_ms']}ms\n")
        console.print(f"[dim]Results saved to {args.output}[/dim]")
