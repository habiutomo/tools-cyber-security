"""
Hash Tools Module
Generates hashes and cracks them using wordlists.
"""

import argparse
import hashlib
import sys
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": lambda: hashlib.blake2b(),
    "blake2s": lambda: hashlib.blake2s(),
}

COMMON_WORDLIST = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
    "letmein", "welcome", "shadow", "superman", "michael", "football",
    "password1", "admin", "login", "passw0rd", "test", "guest", "root",
    "toor", "pass", "master", "1234", "12345", "123456789", "1234567890",
    "qwerty123", "letmein1", "welcome1", "hello", "charlie", "donald",
    "password123", "summer", "winter", "spring", "fall", "january",
    "football1", "batman", "access", "thunder", "killer", "love",
    "secret", "mustang", "maggie", "jordan", "harley", "ranger",
    "hunter2", "buster", "thomas", "robert", "soccer", "hockey",
    "george", "andrew", "daniel", "matthew", "jennifer", "jessica",
]

def hash_text(text, algorithm):
    algo_name = algorithm.lower()
    if algo_name not in ALGORITHMS:
        console.print(f"[bold red]Error:[/bold red] Unknown algorithm '{algo_name}'")
        console.print(f"[dim]Available: {', '.join(ALGORITHMS.keys())}[/dim]")
        return None

    if algo_name.startswith("blake2"):
        h = ALGORITHMS[algo_name]()
        h.update(text.encode("utf-8"))
        return h.hexdigest()
    else:
        return hashlib.new(algo_name, text.encode("utf-8")).hexdigest()

def run_generate(raw_args=None):
    parser = argparse.ArgumentParser(description="Hash Generator")
    parser.add_argument("text", nargs="?", help="Text to hash (or use -f for file)")
    parser.add_argument("-f", "--file", help="File to hash")
    parser.add_argument("-a", "--algorithm", nargs="+",
                       default=["md5", "sha1", "sha256", "sha512"],
                       help="Hash algorithm(s)")
    parser.add_argument("--all-algos", action="store_true", help="Use all algorithms")

    args = parser.parse_args(raw_args)

    if args.file:
        if not os.path.isfile(args.file):
            console.print(f"[bold red]Error:[/bold red] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "rb") as f:
            data = f.read()
        text = data.decode("utf-8", errors="ignore")
        title = f"File: {args.file}"
    elif args.text:
        text = args.text
        title = f"Text: {text[:50]}"
    else:
        text = input("[bold cyan]Enter text to hash:[/bold cyan] ")
        title = f"Text: {text[:50]}"

    algorithms = list(ALGORITHMS.keys()) if args.all_algos else [a.lower() for a in args.algorithm]

    console.print(f"\n[bold cyan]{title}[/bold cyan]\n")

    table = Table(title="Generated Hashes", border_style="green", show_lines=True)
    table.add_column("Algorithm", style="bold cyan")
    table.add_column("Hash", style="green")

    for algo in algorithms:
        h = hash_text(text, algo)
        if h:
            table.add_row(algo.upper(), h)

    console.print(table)

def run_crack(raw_args=None):
    parser = argparse.ArgumentParser(description="Hash Cracker")
    parser.add_argument("-H", "--hash", required=True, help="Target hash to crack")
    parser.add_argument("-a", "--algorithm", default="md5", help="Hash algorithm (default: md5)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    parser.add_argument("--common", action="store_true", help="Use built-in common passwords")

    args = parser.parse_args(raw_args)

    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            console.print(f"[bold red]Error:[/bold red] Wordlist not found: {args.wordlist}")
            sys.exit(1)
        with open(args.wordlist, "r", errors="ignore") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    elif args.common:
        wordlist = COMMON_WORDLIST
    else:
        wordlist = COMMON_WORDLIST

    console.print(f"[bold cyan]Target Hash:[/bold cyan] {args.hash}")
    console.print(f"[bold cyan]Algorithm:[/bold cyan] {args.algorithm.upper()}")
    console.print(f"[bold cyan]Wordlist:[/bold cyan] {len(wordlist)} words\n")

    found = False
    for i, word in enumerate(wordlist, 1):
        h = hash_text(word, args.algorithm)
        if h and h.lower() == args.hash.lower():
            console.print(f"\n[bold green]FOUND![/bold green] '{word}' (attempt #{i})")
            console.print(f"[bold green]Hash:[/bold green] {h}")
            found = True
            break

        if i % 100 == 0:
            console.print(f"[dim]  Tried {i}/{len(wordlist)} words...[/dim]", end="\r")

    if not found:
        console.print(f"\n[bold red]Not found[/bold red] in {len(wordlist)} words")

# Alias for main CLI
run = run_generate
