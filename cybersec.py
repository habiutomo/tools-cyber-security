#!/usr/bin/env python3
"""
CyberSec Tools - Collection of Cybersecurity CLI Tools
Usage: python cybersec.py <module> [options]
"""

import sys
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = Text()
BANNER.append("  _____ _   _ ______   _____                          \n", style="bold cyan")
BANNER.append(" / ____| \\ | |  ____| / ____|                         \n", style="bold cyan")
BANNER.append("| |    |  \\| | |__   | |    _   _ _ __ ___   ___ _ __ \n", style="bold cyan")
BANNER.append("| |    | . ` |  __|  | |   | | | | '_ ` _ \\ / _ \\ '_ \\\n", style="bold cyan")
BANNER.append("| |____| |\\  | |     | |___| |_| | | | | | |  __/ | | |\n", style="bold cyan")
BANNER.append(" \\_____|_| \\_|_|      \\_____\\__,_|_| |_| |_|\\___|_| |_|\n", style="bold cyan")
BANNER.append("\n  Cybersecurity CLI Tools v2.0.0", style="bold yellow")
BANNER.append("\n  Use --help for available modules\n", style="dim")

MODULES = {
    "portscan":    {"desc": "Port Scanner - Scan open ports on target",          "func": "modules.port_scanner.run"},
    "hostdisco":   {"desc": "Host Discovery - Discover live hosts in network",   "func": "modules.host_discovery.run"},
    "pingsweep":   {"desc": "Ping Sweep - ICMP ping sweep network range",       "func": "modules.ping_sweep.run"},
    "traceroute":  {"desc": "Traceroute - Trace network path to target",        "func": "modules.traceroute_mod.run"},
    "subdomain":   {"desc": "Subdomain Enum - Enumerate subdomains",            "func": "modules.subdomain_enum.run"},
    "revip":       {"desc": "Reverse IP - Find all domains on an IP",           "func": "modules.reverse_ip.run"},
    "dnslookup":   {"desc": "DNS Lookup - Query DNS records",                   "func": "modules.dns_lookup.run"},
    "whois":       {"desc": "WHOIS Lookup - Query domain registration info",     "func": "modules.whois_lookup.run"},
    "sslcheck":    {"desc": "SSL/TLS Check - Analyze certificate & protocols",   "func": "modules.ssl_checker.run"},
    "headers":     {"desc": "Header Analyzer - Analyze HTTP security headers",   "func": "modules.header_analyzer.run"},
    "httpmethods": {"desc": "HTTP Methods - Test for dangerous HTTP methods",    "func": "modules.http_methods.run"},
    "cors":        {"desc": "CORS Check - Detect CORS misconfigurations",       "func": "modules.cors_checker.run"},
    "redirect":    {"desc": "Open Redirect - Detect open redirect vulns",       "func": "modules.open_redirect.run"},
    "pwdgen":      {"desc": "Password Generator - Generate secure passwords",    "func": "modules.password_tools.run_generate"},
    "pwdcheck":    {"desc": "Password Check - Check password strength",          "func": "modules.password_tools.run_check"},
    "hashgen":     {"desc": "Hash Generator - Generate hashes from text",        "func": "modules.hash_tools.run_generate"},
    "hashcrack":   {"desc": "Hash Cracker - Crack hashes with wordlist",         "func": "modules.hash_tools.run_crack"},
    "urlcheck":    {"desc": "URL Checker - Check URL for phishing/malware",      "func": "modules.url_checker.run"},
    "dirbust":     {"desc": "Dir Bruteforce - Brute force directories/files",    "func": "modules.dir_bruteforce.run"},
    "sensfiles":   {"desc": "Sensitive Files - Find .env, .git, backups",        "func": "modules.sensitive_finder.run"},
    "emailosint":  {"desc": "Email OSINT - Gather info from email address",      "func": "modules.email_osint.run"},
    "userosint":   {"desc": "Username OSINT - Find username across platforms",    "func": "modules.osint_username.run"},
    "wifi":        {"desc": "WiFi Scanner - Scan nearby WiFi networks",          "func": "modules.wifi_scanner.run"},
    "wafdetect":   {"desc": "WAF Detection - Detect Web Application Firewall",   "func": "modules.waf_detect.run"},
    "techdetect":  {"desc": "Tech Detect - Detect technologies on website",      "func": "modules.tech_detect.run"},
    "takeover":    {"desc": "Subdomain Takeover - Check for takeover vulns",     "func": "modules.subdomain_takeover.run"},
}

def run_module(module_name, args):
    func_path = MODULES[module_name]["func"]
    module_path, func_name = func_path.rsplit(".", 1)
    mod = __import__(module_path, fromlist=[func_name])
    func = getattr(mod, func_name)
    func(args)

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        console.print(Panel(BANNER, border_style="cyan", padding=(1, 2)))
        console.print("[bold white]Available Modules:[/bold white]\n")
        for name, info in MODULES.items():
            console.print(f"  [bold cyan]{name:14}[/bold cyan] {info['desc']}")
        console.print(f"\n[dim]Usage: python cybersec.py <module> [options][/dim]")
        console.print(f"[dim]Example: python cybersec.py portscan -t 192.168.1.1[/dim]")
        sys.exit(0)

    module_name = sys.argv[1].lower()
    if module_name not in MODULES:
        console.print(f"[bold red]Error:[/bold red] Unknown module '{module_name}'")
        console.print(f"[dim]Run with --help to see available modules[/dim]")
        sys.exit(1)

    remaining_args = sys.argv[2:]
    run_module(module_name, remaining_args)

if __name__ == "__main__":
    main()
