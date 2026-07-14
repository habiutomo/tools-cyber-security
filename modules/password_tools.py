"""
Password Tools Module
Generates secure passwords and checks password strength.
"""

import argparse
import random
import string
import math
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
    "letmein", "welcome", "shadow", "superman", "michael", "football",
    "password1", "password123", "admin", "login", "passw0rd"
]

def generate_password(length=16, uppercase=True, lowercase=True, digits=True, special=True, exclude=""):
    charset = ""
    required = []
    if uppercase:
        chars = string.ascii_uppercase
        if exclude:
            chars = "".join(c for c in chars if c not in exclude)
        charset += chars
        required.append(random.choice(chars))
    if lowercase:
        chars = string.ascii_lowercase
        if exclude:
            chars = "".join(c for c in chars if c not in exclude)
        charset += chars
        required.append(random.choice(chars))
    if digits:
        chars = string.digits
        if exclude:
            chars = "".join(c for c in chars if c not in exclude)
        charset += chars
        required.append(random.choice(chars))
    if special:
        chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        if exclude:
            chars = "".join(c for c in chars if c not in exclude)
        charset += chars
        required.append(random.choice(chars))

    if not charset:
        console.print("[bold red]Error:[/bold red] At least one character type required")
        sys.exit(1)

    remaining = length - len(required)
    password = required + [random.choice(charset) for _ in range(remaining)]
    random.shuffle(password)
    return "".join(password)

def check_strength(password):
    score = 0
    feedback = []
    length = len(password)

    if length >= 8: score += 1
    if length >= 12: score += 1
    if length >= 16: score += 1
    if length >= 20: score += 1

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    char_types = sum([has_upper, has_lower, has_digit, has_special])
    score += char_types

    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_special: score += 1

    # Entropy calculation
    charset_size = 0
    if has_upper: charset_size += 26
    if has_lower: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 32
    if charset_size == 0: charset_size = 26
    entropy = length * math.log2(charset_size)

    if entropy > 60: score += 2
    if entropy > 80: score += 2
    if entropy > 100: score += 2

    # Penalties
    if password.lower() in COMMON_PASSWORDS:
        score -= 10
        feedback.append("[red]Password is a common password![/red]")

    if length < 8:
        feedback.append("[red]Too short (minimum 8 characters)[/red]")

    if char_types < 2:
        feedback.append("[yellow]Use more character types[/yellow]")

    # Sequential check
    sequential = 0
    for i in range(len(password) - 2):
        if ord(password[i+1]) == ord(password[i]) + 1 == ord(password[i+2]) - 2:
            sequential += 1
    if sequential > 0:
        score -= sequential
        feedback.append("[yellow]Contains sequential characters[/yellow]")

    # Repeated check
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            score -= 2
            feedback.append("[yellow]Contains repeated characters[/yellow]")
            break

    if not feedback:
        feedback.append("[green]No obvious weaknesses detected[/green]")

    score = max(0, min(score, 30))

    if score >= 20:
        strength = "VERY STRONG"
        color = "green"
    elif score >= 15:
        strength = "STRONG"
        color = "green"
    elif score >= 10:
        strength = "MODERATE"
        color = "yellow"
    elif score >= 5:
        strength = "WEAK"
        color = "red"
    else:
        strength = "VERY WEAK"
        color = "red"

    return {
        "strength": strength,
        "color": color,
        "score": score,
        "max_score": 30,
        "entropy": round(entropy, 2),
        "length": length,
        "char_types": char_types,
        "feedback": feedback
    }

def run_generate(raw_args=None):
    parser = argparse.ArgumentParser(description="Password Generator")
    parser.add_argument("-l", "--length", type=int, default=16, help="Password length (default: 16)")
    parser.add_argument("-n", "--count", type=int, default=5, help="Number of passwords to generate")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-special", action="store_true", help="Exclude special characters")
    parser.add_argument("--exclude", default="", help="Characters to exclude")

    args = parser.parse_args(raw_args)

    console.print(Panel(
        f"[bold cyan]Length:[/bold cyan] {args.length}\n"
        f"[bold cyan]Count:[/bold cyan] {args.count}\n"
        f"[bold cyan]Uppercase:[/bold cyan] {'No' if args.no_upper else 'Yes'}\n"
        f"[bold cyan]Lowercase:[/bold cyan] {'No' if args.no_lower else 'Yes'}\n"
        f"[bold cyan]Digits:[/bold cyan] {'No' if args.no_digits else 'Yes'}\n"
        f"[bold cyan]Special:[/bold cyan] {'No' if args.no_special else 'Yes'}",
        title="[bold]Password Generator[/bold]", border_style="cyan"
    ))

    table = Table(border_style="green")
    table.add_column("#", style="dim")
    table.add_column("Password", style="bold green")
    table.add_column("Strength", style="cyan")
    table.add_column("Entropy", style="yellow")

    for i in range(args.count):
        pwd = generate_password(
            length=args.length,
            uppercase=not args.no_upper,
            lowercase=not args.no_lower,
            digits=not args.no_digits,
            special=not args.no_special,
            exclude=args.exclude
        )
        info = check_strength(pwd)
        table.add_row(str(i+1), pwd, info["strength"], f"{info['entropy']} bits")

    console.print(table)

def run_check(raw_args=None):
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("password", nargs="?", help="Password to check (or enter interactively)")

    args = parser.parse_args(raw_args)

    if not args.password:
        import getpass
        password = getpass.getpass("[bold cyan]Enter password to check:[/bold cyan] ")
    else:
        password = args.password

    info = check_strength(password)

    console.print(Panel(
        f"[bold {info['color']}]Strength: {info['strength']}[/bold {info['color']}]\n"
        f"[bold cyan]Score:[/bold cyan] {info['score']}/{info['max_score']}\n"
        f"[bold cyan]Length:[/bold cyan] {info['length']}\n"
        f"[bold cyan]Character Types:[/bold cyan] {info['char_types']}/4\n"
        f"[bold cyan]Entropy:[/bold cyan] {info['entropy']} bits\n"
        f"\n[bold white]Feedback:[/bold white]\n" +
        "\n".join(f"  - {f}" for f in info['feedback']),
        title="[bold]Password Analysis[/bold]", border_style=info['color']
    ))

# Alias for main CLI
run = run_generate
